package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

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
		}
		data = append(data, _p)
	}
	return data
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
	}
	data = append(data, _p)
	return data
}

// permTarget holds the validated flags shared by the permission commands.
type permTarget struct {
	username, envName string
	access            users.EnvAccess
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
	if t.access.Admin { // admin implies everything
		t.access.User, t.access.Query, t.access.Carve = true, true, true
	}
	return t, nil
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
		out[uuid] = users.EnvAccess{User: a.User, Query: a.Query, Carve: a.Carve, Admin: a.Admin}
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
	if dbFlag {
		// No lockout guard: change is additive and never demotes anyone.
		if err := adminUsers.ChangeAccess(t.username, uuid, merged); err != nil {
			return fmt.Errorf("error setting permissions - %w", err)
		}
		auditlogsmgr.Permissions(getShellUsername(), "changed permissions for user "+t.username, "CLI", envID)
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
		auditlogsmgr.Permissions(getShellUsername(), "reset permissions for user "+t.username, "CLI", envID)
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
