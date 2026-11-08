package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

// Helper function to convert user permissions into the data expected for output
func permissionsToData(perms users.UserAccess, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for e, p := range perms {
		_p := []string{
			e,
			stringifyBool(p.User),
			stringifyBool(p.Admin),
			stringifyBool(p.Query),
			stringifyBool(p.Carve),
			tierOrNone(p.QueryTier),
			tierOrNone(p.CarveTier),
			scopeTagLabels(e, p.ScopeTags),
		}
		data = append(data, _p)
	}
	return data
}

func tierOrNone(t string) string {
	if t == "" {
		return users.TierNone.String()
	}
	return t
}

// envTags lists the tags of an environment (by name or UUID), in either mode.
func envTags(env string, envID uint) ([]tags.AdminTag, error) {
	var all []tags.AdminTag
	var err error
	switch {
	case dbFlag:
		all, err = tagsmgr.GetByEnv(envID)
	case apiFlag:
		all, err = osctrlAPI.GetTags(env)
	default:
		return nil, errors.New("no mode selected")
	}
	if err != nil {
		return nil, fmt.Errorf("error getting tags - %w", err)
	}
	out := all[:0:0]
	for _, t := range all {
		if t.EnvironmentID == envID {
			out = append(out, t)
		}
	}
	return out, nil
}

// resolveScopeTags maps tag names to IDs in the environment. An unknown name
// (including a tag of another environment) or a sensitive tag is an error.
func resolveScopeTags(envName string, envID uint, names []string) ([]uint, error) {
	ids := []uint{}
	if len(names) == 0 {
		return ids, nil
	}
	envTgs, err := envTags(envName, envID)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]tags.AdminTag, len(envTgs))
	for _, t := range envTgs {
		byName[t.Name] = t
	}
	for _, n := range names {
		t, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("tag %q not found in environment %s", n, envName)
		}
		if t.Sensitive {
			return nil, errors.New("sensitive tag cannot be a scope tag")
		}
		ids = append(ids, t.ID)
	}
	return ids, nil
}

// scopeTagLabels renders tag names when resolvable in the environment, else IDs.
func scopeTagLabels(env string, ids []uint) string {
	if len(ids) == 0 {
		return ""
	}
	names := map[uint]string{}
	if _, envID, err := permEnv(env); err == nil {
		if tgs, err := envTags(env, envID); err == nil {
			for _, t := range tgs {
				names[t.ID] = t.Name
			}
		}
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, strconv.FormatUint(uint64(id), 10))
		}
	}
	return strings.Join(out, ",")
}

// Helper function
func accessToData(access users.EnvAccess, env string, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_p := []string{
		env,
		stringifyBool(access.User),
		stringifyBool(access.Admin),
		stringifyBool(access.Query),
		stringifyBool(access.Carve),
		tierOrNone(access.QueryTier),
		tierOrNone(access.CarveTier),
		scopeTagLabels(env, access.ScopeTags),
	}
	data = append(data, _p)
	return data
}

// permTarget holds the validated flags shared by the permission commands.
type permTarget struct {
	username, envName string
	access            users.EnvAccess
	queryTier         string // set only when --query-tier was given
	carveTier         string
	scopeTags         []string
	scopeTagsSet      bool
}

func permFlags(cmd *cli.Command, needEnv bool) (permTarget, error) {
	t := permTarget{username: cmd.String("username"), envName: cmd.String("environment")}
	if t.username == "" {
		return t, errors.New("username is required")
	}
	if needEnv && t.envName == "" {
		return t, errors.New("environment is required")
	}
	t.access = users.EnvAccess{User: cmd.Bool("user"), Query: cmd.Bool("query"), Carve: cmd.Bool("carve"), Admin: cmd.Bool("admin")}
	for _, f := range []struct {
		flag string
		dst  *string
	}{{"query-tier", &t.queryTier}, {"carve-tier", &t.carveTier}} {
		if v := cmd.String(f.flag); v != "" {
			if _, err := users.ParseTier(v); err != nil {
				return t, fmt.Errorf("invalid --%s %q (none, tags, standard or full)", f.flag, v)
			}
			*f.dst = v
		}
	}
	if t.scopeTagsSet = cmd.IsSet("scope-tags"); t.scopeTagsSet {
		t.scopeTags = []string{}
		for _, n := range strings.Split(cmd.String("scope-tags"), ",") {
			if n = strings.TrimSpace(n); n != "" {
				t.scopeTags = append(t.scopeTags, n)
			}
		}
	}
	if t.access.Admin && (t.queryTier == users.TierNone.String() || t.carveTier == users.TierNone.String()) {
		return t, errors.New("--admin implies query and carve access; it cannot be combined with --query-tier none or --carve-tier none")
	}
	if t.access.Admin { // admin implies everything
		t.access.User, t.access.Query, t.access.Carve = true, true, true
	}
	return t, nil
}

// applyTiers sets the tiers given on the command line and the matching
// booleans (the boolean is authoritative when it disagrees with the tier).
func (t permTarget) applyTiers(a *users.EnvAccess) {
	if t.queryTier != "" {
		a.QueryTier, a.Query = t.queryTier, t.queryTier != users.TierNone.String()
	}
	if t.carveTier != "" {
		a.CarveTier, a.Carve = t.carveTier, t.carveTier != users.TierNone.String()
	}
}

func defaultTier(tier string, on bool) string {
	if tier != "" {
		return tier
	}
	if on {
		return users.TierStandard.String()
	}
	return users.TierNone.String()
}

// auditSuffix describes the tier and scope tag flags for the audit entry.
func (t permTarget) auditSuffix() string {
	var parts []string
	if t.queryTier != "" {
		parts = append(parts, "query tier "+t.queryTier)
	}
	if t.carveTier != "" {
		parts = append(parts, "carve tier "+t.carveTier)
	}
	if t.scopeTagsSet {
		parts = append(parts, "scope tags ["+strings.Join(t.scopeTags, ",")+"]")
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// permEnv resolves an environment name to its UUID (and DB ID, DB mode only).
func permEnv(envName string) (string, uint, error) {
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return "", 0, fmt.Errorf("error getting environment - %w", err)
		}
		return env.UUID, env.ID, nil
	} else if apiFlag {
		env, err := osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return "", 0, fmt.Errorf("error getting environment - %w", err)
		}
		return env.UUID, env.ID, nil
	}
	return "", 0, errors.New("no mode selected")
}

// dbUserAccess and apiUserAccess return the access of a user per environment
// UUID. An environment without rows is absent (reads as all-false).
func dbUserAccess(username string) (users.UserAccess, error) {
	access, err := adminUsers.GetAccess(username)
	if err != nil {
		return nil, fmt.Errorf("error getting access - %w", err)
	}
	return access, nil
}

func apiUserAccess(username string) (users.UserAccess, error) {
	resp, err := osctrlAPI.GetUserPermissions(username)
	if err != nil {
		return nil, fmt.Errorf("error getting access - %w", err)
	}
	out := make(users.UserAccess, len(resp.Permissions))
	for uuid, a := range resp.Permissions {
		out[uuid] = users.EnvAccess{User: a.User, Query: a.Query, Carve: a.Carve, Admin: a.Admin, QueryTier: a.QueryTier, CarveTier: a.CarveTier, ScopeTags: a.ScopeTags}
	}
	return out, nil
}

// dbLockoutActor is the identity compared with the target in the DB-mode
// lockout guard: the shell user (also without the "env: " display prefix, so a
// shell user named like the osctrl user counts as that user).
func dbLockoutActor(target string) string {
	actor := getShellUsername()
	if strings.TrimPrefix(actor, "env: ") == target {
		return target
	}
	return actor
}

// dbLockoutGuard (users.CheckLockout, shared with the handler) refuses, before
// any write, demoting the last super-admin and, in DB mode, demoting yourself
// only when you are a global super-admin; the API handler
// (SetUserPermissionsHandler) refuses self-demotion for anyone.
func dbLockoutGuard(target string, access users.EnvAccess) error {
	err := adminUsers.CheckLockout(dbLockoutActor(target), target, access)
	if errors.Is(err, users.ErrSelfDemote) {
		return fmt.Errorf("%w (you are %q: set USER= to act as another user; better, have another super-admin do it)", err, target)
	}
	return err
}

// Change is read-modify-write in both modes (read current access, OR in the
// flags, write all four levels): a concurrent change to the same user and
// environment between the read and the write can be overwritten.
func changePermissions(ctx context.Context, cmd *cli.Command) error {
	t, err := permFlags(cmd, true)
	if err != nil {
		return err
	}
	uuid, envID, err := permEnv(t.envName)
	if err != nil {
		return err
	}
	var existing users.UserAccess
	if dbFlag {
		existing, err = dbUserAccess(t.username)
	} else if apiFlag {
		existing, err = apiUserAccess(t.username)
	}
	if err != nil {
		return err
	}
	cur := existing[uuid]
	merged := users.EnvAccess{
		User:  cur.User || t.access.User,
		Query: cur.Query || t.access.Query,
		Carve: cur.Carve || t.access.Carve,
		Admin: cur.Admin || t.access.Admin,
	}
	if merged.Admin {
		merged.User, merged.Query, merged.Carve = true, true, true
	}
	t.applyTiers(&merged)
	if t.scopeTagsSet {
		if merged.ScopeTags, err = resolveScopeTags(t.envName, envID, t.scopeTags); err != nil {
			return err
		}
	}
	if dbFlag {
		// No lockout guard: change is additive and never demotes anyone.
		if err := adminUsers.ChangeAccess(t.username, uuid, merged); err != nil {
			return fmt.Errorf("error setting permissions - %w", err)
		}
		if t.scopeTagsSet {
			if err := adminUsers.SetScopeTags(t.username, uuid, getShellUsername(), merged.ScopeTags); err != nil {
				return fmt.Errorf("error setting scope tags - %w", err)
			}
		}
		auditlogsmgr.Permissions(getShellUsername(), "changed permissions for user "+t.username+t.auditSuffix(), "CLI", envID)
	} else if apiFlag {
		if err := osctrlAPI.SetUserPermissions(t.username, uuid, merged); err != nil {
			return fmt.Errorf("error setting permissions - %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ permissions changed for user %s successfully\n", t.username)
	}
	return nil
}

func showPermissions(ctx context.Context, cmd *cli.Command) error {
	t, err := permFlags(cmd, true)
	if err != nil {
		return err
	}
	uuid, _, err := permEnv(t.envName)
	if err != nil {
		return err
	}
	var existing users.UserAccess
	if dbFlag {
		existing, err = dbUserAccess(t.username)
	} else if apiFlag {
		existing, err = apiUserAccess(t.username)
	}
	if err != nil {
		return err
	}
	access, envName := existing[uuid], t.envName
	header := []string{
		"Environment",
		"User access",
		"Admin access",
		"Query access",
		"Carve access",
		"Query tier",
		"Carve tier",
		"Scope tags",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(access)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := accessToData(access, envName, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := accessToData(access, envName, nil)
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func resetPermissions(ctx context.Context, cmd *cli.Command) error {
	t, err := permFlags(cmd, true)
	if err != nil {
		return err
	}
	uuid, envID, err := permEnv(t.envName)
	if err != nil {
		return err
	}
	// Reset is a full replace in both modes: unset tiers become standard/none
	// from the booleans and unset scope tags are cleared.
	t.applyTiers(&t.access)
	t.access.QueryTier = defaultTier(t.access.QueryTier, t.access.Query)
	t.access.CarveTier = defaultTier(t.access.CarveTier, t.access.Carve)
	t.access.ScopeTags = []uint{}
	if t.scopeTagsSet {
		if t.access.ScopeTags, err = resolveScopeTags(t.envName, envID, t.scopeTags); err != nil {
			return err
		}
	}
	if dbFlag {
		if !adminUsers.Exists(t.username) {
			return fmt.Errorf("user %s does not exist", t.username)
		}
		if err := dbLockoutGuard(t.username, t.access); err != nil {
			return err
		}
		if err := adminUsers.DeleteEnvPermissions(t.username, uuid); err != nil {
			return err
		}
		perms := adminUsers.GenPermissions(t.username, appName, adminUsers.GenEnvUserAccess([]string{uuid}, t.access.User, t.access.Query, t.access.Carve, t.access.Admin))
		if err := adminUsers.CreatePermissions(perms); err != nil {
			return err
		}
		if err := adminUsers.ChangeAccess(t.username, uuid, t.access); err != nil {
			return fmt.Errorf("error setting tiers - %w", err)
		}
		if err := adminUsers.SetScopeTags(t.username, uuid, getShellUsername(), t.access.ScopeTags); err != nil {
			return fmt.Errorf("error setting scope tags - %w", err)
		}
		auditlogsmgr.Permissions(getShellUsername(), "reset permissions for user "+t.username+t.auditSuffix(), "CLI", envID)
	} else if apiFlag {
		if err := osctrlAPI.SetUserPermissions(t.username, uuid, t.access); err != nil {
			return fmt.Errorf("error setting permissions - %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ permissions reset for user %s successfully\n", t.username)
	}
	return nil
}

func allPermissions(ctx context.Context, cmd *cli.Command) error {
	t, err := permFlags(cmd, false)
	if err != nil {
		return err
	}
	var existingAccess users.UserAccess
	if dbFlag {
		existingAccess, err = dbUserAccess(t.username)
	} else if apiFlag {
		existingAccess, err = apiUserAccess(t.username)
	}
	if err != nil {
		return err
	}

	header := []string{
		"Environment",
		"User access",
		"Admin access",
		"Query access",
		"Carve access",
		"Query tier",
		"Carve tier",
		"Scope tags",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(existingAccess)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := permissionsToData(existingAccess, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := permissionsToData(existingAccess, nil)
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}
