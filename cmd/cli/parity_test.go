package main

// Parity rig: runs one osctrl-cli command line in DB mode and in API mode
// against the same sqlite database, so a test can compare the two.
//
// Wiring: the REAL API handlers, no Redis.
//   - One sqlite file in t.TempDir(), described by a YAML db config. RunDB
//     passes it with --db -D, so the CLI opens it through the real
//     cliWrapperMode init path. The rig opens it once more (rig.DB) with
//     backend.CreateDBManagerFile, the opener osctrl-api uses.
//   - The API side is handlers.CreateHandlersApi(...) over rig.DB (users with
//     JWT, environments, settings, tags, nodes, alerts, service commands,
//     audit log), served by httptest.NewServer. RunAPI passes its URL and a
//     token with --api-url/--api-token, so the CLI builds its own client
//     exactly as in production. EnvCache and Redis stay nil: the handlers
//     skip cache invalidation when EnvCache is nil.
//   - registerRoutes and handlerAuthCheck live in package main of cmd/api and
//     cannot be imported, so parityRoutes copies the route patterns and
//     parityAuth repeats the JWT branch of handlerAuthCheck (signature check,
//     match against the user's stored APIToken, same request context). Not
//     applied: rate limits, CSRF (bearer-only clients are exempt anyway), the
//     --alerts-enabled gate.
//
// Routes served (copied from cmd/api/main.go registerRoutes; add what a new
// parity test needs, with the same pattern and handler):
//   - checks-auth
//   - environments: list, get, map, actions, create/update/delete, enroll and
//     remove values and actions, enroll cert upload, assembled configuration,
//     config GET/PATCH, intervals and expiration PATCH
//   - users: list, get, me, permissions GET/POST, permissions/all, token
//     refresh/delete, user actions
//   - settings: list, by service, by service+env, PATCH
//   - carves: complete/delete/expire action
//   - alerts: rules and channels CRUD, channel types/test, history, apply

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	parityJWTSecret = "parity-test-jwt-secret-0123456789abcdef"
	// parityContextAPI is contextAPI in cmd/api/auth.go and
	// cmd/api/handlers/utils.go (unexported there).
	parityContextAPI = "osctrl-api-context"
)

type parityRig struct {
	t *testing.T
	// DB is the sqlite database both modes use.
	DB *gorm.DB
	// Users (with JWT) and Envs are the managers the API handlers use, on DB.
	Users *users.UserManager
	Envs  *environments.EnvManager
	// URL is the in-process API server ("http://127.0.0.1:port").
	URL string
	// AdminToken is the API token of the seeded global admin "admin".
	AdminToken string
	// API is a client for URL authenticated as "admin".
	API *apiclient.OsctrlAPI
	// DBConfigFile is the YAML db config RunDB passes with -D.
	DBConfigFile string
}

// newParityRig seeds environment "dev" and global admin "admin", starts the
// API server, and restores every CLI global it or its runs touch on cleanup.
// No t.Parallel(): stdout and flags are process-global.
func newParityRig(t *testing.T) *parityRig {
	t.Helper()
	restore := saveCLIGlobals()
	t.Cleanup(restore)
	dir := t.TempDir()
	r := &parityRig{t: t, DBConfigFile: filepath.Join(dir, "db.yml")}
	require.NoError(t, os.WriteFile(r.DBConfigFile, []byte("db:\n  type: sqlite\n  filePath: "+filepath.Join(dir, "osctrl.db")+"\n"), 0o600))
	dbm, err := backend.CreateDBManagerFile(r.DBConfigFile)
	require.NoError(t, err)
	r.DB = dbm.Conn
	r.DB.Logger = logger.Discard
	t.Cleanup(func() {
		if sqlDB, err := r.DB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	r.Users = users.CreateUserManager(r.DB).WithJWT(&config.YAMLConfigurationJWT{JWTSecret: parityJWTSecret, HoursToExpire: 1})
	r.Envs = environments.CreateEnvironment(r.DB)
	audit, err := auditlog.CreateAuditLogManager(r.DB, "osctrl-api", true)
	require.NoError(t, err)
	h := handlers.CreateHandlersApi(
		handlers.WithDB(r.DB),
		handlers.WithUsers(r.Users),
		handlers.WithEnvs(r.Envs),
		handlers.WithSettings(settings.NewSettings(r.DB)),
		handlers.WithTags(tags.CreateTagManager(r.DB)),
		handlers.WithNodes(nodes.CreateNodes(r.DB)),
		handlers.WithMFA(mfa.NewManager(r.DB), nil, false, ""),
		handlers.WithQueries(queries.CreateQueries(r.DB)),
		handlers.WithAlerts(alerts.NewManager(r.DB)),
		handlers.WithServiceCommands(servicecommands.NewManager(r.DB)),
		handlers.WithAuditLog(audit),
		handlers.WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		handlers.WithJWTSecret([]byte(parityJWTSecret)),
	)
	mux := http.NewServeMux()
	for _, rt := range parityRoutes {
		m := reflect.ValueOf(h).MethodByName(rt.handler)
		require.True(t, m.IsValid(), "HandlersApi has no handler %s", rt.handler)
		hf, ok := m.Interface().(func(http.ResponseWriter, *http.Request))
		require.True(t, ok, "HandlersApi has no handler %s", rt.handler)
		mux.Handle(rt.pattern, parityAuth(r.Users, hf))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r.URL = srv.URL
	r.SeedEnv("dev")
	r.AdminToken = r.SeedUser("admin", true)
	r.API, err = apiclient.CreateAPI(apiclient.JSONConfigurationAPI{URL: r.URL, Token: r.AdminToken}, false)
	require.NoError(t, err)
	return r
}

// SeedEnv creates environment name with the manager calls `env add` makes in
// DB mode (UUID, secrets, configuration parts, flags) but creates NO tag:
// both DB-mode `env add` (tagsmgr.NewTag) and the API's
// EnvironmentCreateHandler (h.Tags.NewTag) create a tag named after the
// environment, so tests comparing tags must account for its absence here.
func (r *parityRig) SeedEnv(name string) environments.TLSEnvironment {
	r.t.Helper()
	env := r.Envs.Empty(name, name+".example.com")
	env.Configuration = r.Envs.GenEmptyConfiguration(true)
	env.EnrollExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
	env.RemoveExpire = env.EnrollExpire
	require.NoError(r.t, r.Envs.Create(&env))
	cnf, err := r.Envs.GenStructConf([]byte(env.Configuration))
	require.NoError(r.t, err)
	require.NoError(r.t, r.Envs.UpdateConfigurationParts(name, cnf))
	flags, err := r.Envs.GenerateFlags(env, "", "", config.YAMLConfigurationOsquery{Config: true, Logger: true, Query: true, Carve: true})
	require.NoError(r.t, err)
	require.NoError(r.t, r.Envs.UpdateFlags(name, flags))
	env, err = r.Envs.Get(name)
	require.NoError(r.t, err)
	return env
}

// SeedUser creates user name (global admin if admin) and returns a valid API
// token for it. A non-admin has no environment access; grant it with
// r.Users.SetEnvLevel(name, envUUID, users.UserLevel|users.AdminLevel, true).
func (r *parityRig) SeedUser(name string, admin bool) string {
	r.t.Helper()
	u, err := r.Users.New(name, "", "", "", admin, false)
	require.NoError(r.t, err)
	require.NoError(r.t, r.Users.Create(u))
	token, exp, err := r.Users.CreateToken(name, "osctrl-api", 1)
	require.NoError(r.t, err)
	require.NoError(r.t, r.Users.UpdateToken(name, token, exp))
	return token
}

// RunDB runs `osctrl-cli --db -D <rig db> <args...>` through the real command
// tree and wrapper, returning what the command wrote to stdout. Global flags
// (for example "-o", "json") may lead args.
//
// os.Exit hazard (RunDB, RunAPI, RunAPIAs): many actions call os.Exit on
// argument-validation paths (missing --name/--username/--environment,
// "already exists", invalid target/type), in settings.go, permission.go,
// environment.go, tag.go, query.go, carve.go, node.go and user.go. Through the
// rig that kills the test binary. Rule for later tasks: use the rig only on
// paths that return errors, and when a task edits a command, convert the
// os.Exit validations in THAT command into returned errors (main() already
// prints "❌ <err>" to stderr and exits 1).
func (r *parityRig) RunDB(args ...string) (string, error) {
	r.t.Helper()
	return r.run(append([]string{"--db", "-D", r.DBConfigFile}, args...))
}

// RunAPI runs `osctrl-cli --api-url <rig> --api-token <admin> <args...>`.
func (r *parityRig) RunAPI(args ...string) (string, error) {
	r.t.Helper()
	return r.RunAPIAs(r.AdminToken, args...)
}

// RunAPIAs is RunAPI authenticated with token (from SeedUser).
func (r *parityRig) RunAPIAs(token string, args ...string) (string, error) {
	r.t.Helper()
	return r.run(append([]string{"--db=false", "--api", "-A", "", "-U", r.URL, "-T", token}, args...))
}

func (r *parityRig) run(args []string) (string, error) {
	r.t.Helper()
	restore := saveCLIGlobals()
	defer restore()
	defer func() {
		// The wrapper opens its own connection on every DB-mode run.
		if db != nil && db.Conn != nil && db.Conn != r.DB {
			if sqlDB, err := db.Conn.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
	}()
	pr, pw, err := os.Pipe()
	require.NoError(r.t, err)
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&out, pr); close(done) }()
	stdout := os.Stdout
	os.Stdout = pw
	// A fresh copy of the tree per run: urfave/cli keeps "was set" state in
	// each flag, so reusing the tree makes cmd.IsSet true for a flag given
	// to an earlier run.
	root := cloneCommand(&cli.Command{Name: appName, Flags: flags, Commands: commands})
	runErr := func() error {
		// Deferred so a panicking command cannot leave os.Stdout on the pipe.
		defer func() {
			os.Stdout = stdout
			_ = pw.Close()
			<-done
			_ = pr.Close()
		}()
		return root.Run(context.Background(), append([]string{appName}, args...))
	}()
	return out.String(), runErr
}

// cloneCommand copies c, its flags and its subcommands. Only copies are ever
// run, so the originals keep their never-parsed state.
func cloneCommand(c *cli.Command) *cli.Command {
	n := *c
	n.Flags = make([]cli.Flag, len(c.Flags))
	for i, f := range c.Flags {
		v := reflect.ValueOf(f)
		nv := reflect.New(v.Elem().Type())
		nv.Elem().Set(v.Elem())
		n.Flags[i] = nv.Interface().(cli.Flag)
	}
	n.Commands = make([]*cli.Command, len(c.Commands))
	for i, sc := range c.Commands {
		n.Commands[i] = cloneCommand(sc)
	}
	return &n
}

// saveCLIGlobals snapshots every global the wrapper, the flags or an action
// writes, and returns the function that puts them back.
func saveCLIGlobals() func() {
	oDB, oAPI, oSilent, oInsecure, oVerbose, oWrite, oFormat := dbFlag, apiFlag, silentFlag, insecureFlag, verboseFlag, writeApiFileFlag, formatFlag
	oDBFile, oAPIFile, oAPIConfig, oDBConfig := dbConfigFile, apiConfigFile, apiConfig, *dbConfig
	oClient, oConn, oErr, oLevel := osctrlAPI, db, err, zerolog.GlobalLevel()
	oUsers, oEnvs, oSettings, oNodes, oQueries, oCarves, oTags, oAudit, oMFA := adminUsers, envs, settingsmgr, nodesmgr, queriesmgr, filecarves, tagsmgr, auditlogsmgr, mfamgr
	return func() {
		dbFlag, apiFlag, silentFlag, insecureFlag, verboseFlag, writeApiFileFlag, formatFlag = oDB, oAPI, oSilent, oInsecure, oVerbose, oWrite, oFormat
		dbConfigFile, apiConfigFile, apiConfig, *dbConfig = oDBFile, oAPIFile, oAPIConfig, oDBConfig
		osctrlAPI, db, err = oClient, oConn, oErr
		zerolog.SetGlobalLevel(oLevel)
		adminUsers, envs, settingsmgr, nodesmgr, queriesmgr, filecarves, tagsmgr, auditlogsmgr, mfamgr = oUsers, oEnvs, oSettings, oNodes, oQueries, oCarves, oTags, oAudit, oMFA
	}
}

// parityAuth is a copy of the JWT branch of handlerAuthCheck in
// cmd/api/auth.go (CSRF left out: bearer-only clients are exempt). The route
// drift guard does not cover it: re-check it by hand when auth.go changes.
func parityAuth(um *users.UserManager, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer"))
		claims, valid := um.CheckToken(parityJWTSecret, token)
		user, err := um.Get(claims.Username)
		if !valid || err != nil || user.APIToken == "" || user.APIToken != token {
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusUnauthorized, types.ApiErrorResponse{Error: "unauthorized", Code: "unauthorized"})
			return
		}
		if err := um.RecordTokenUse(user, utils.GetIP(req), time.Now()); err != nil {
			log.Err(err).Msgf("error updating token for user %s", claims.Username)
		}
		ctx := users.WithPermissionCache(context.WithValue(req.Context(), handlers.ContextKey(parityContextAPI), handlers.ContextValue{"user": claims.Username}))
		users.CacheAuthenticatedUser(ctx, user)
		h.ServeHTTP(w, req.WithContext(ctx))
	})
}

// parityRoutes are the cmd/api registerRoutes routes the rig serves: the
// pattern and the HandlersApi method name. TestParityRoutesExistInAPI checks
// each one still exists in cmd/api/main.go with the same handler.
var parityRoutes = []struct{ pattern, handler string }{
	// parityRoutes are the cmd/api registerRoutes patterns the parity tests use.
	{"GET /api/v1/checks-auth", "CheckHandlerAuth"},
	// environments
	{"GET /api/v1/environments", "EnvironmentsHandler"},
	{"POST /api/v1/environments/actions", "EnvActionsHandler"},
	{"GET /api/v1/environments/{env}", "EnvironmentHandler"},
	{"GET /api/v1/environments/map/{target}", "EnvironmentMapHandler"},
	{"GET /api/v1/environments/{env}/enroll/{target}", "EnvEnrollHandler"},
	{"GET /api/v1/environments/{env}/configuration/assembled", "EnvConfigurationHandler"},
	{"POST /api/v1/environments/{env}/enroll/cert", "EnvCertUploadHandler"},
	{"POST /api/v1/environments/{env}/enroll/{action}", "EnvEnrollActionsHandler"},
	{"GET /api/v1/environments/{env}/remove/{target}", "EnvRemoveHandler"},
	{"POST /api/v1/environments/{env}/remove/{action}", "EnvRemoveActionsHandler"},
	{"POST /api/v1/environments", "EnvironmentCreateHandler"},
	{"PATCH /api/v1/environments/{env}", "EnvironmentUpdateHandler"},
	{"DELETE /api/v1/environments/{env}", "EnvironmentDeleteHandler"},
	{"GET /api/v1/environments/config/{env}", "EnvironmentConfigHandler"},
	{"PATCH /api/v1/environments/config/{env}", "EnvironmentConfigPatchHandler"},
	{"PATCH /api/v1/environments/intervals/{env}", "EnvironmentIntervalsPatchHandler"},
	{"PATCH /api/v1/environments/expiration/{env}", "EnvironmentExpirationPatchHandler"},
	// users
	{"GET /api/v1/users/me", "MeHandler"},
	{"GET /api/v1/users/{username}", "UserHandler"},
	{"GET /api/v1/users", "UsersHandler"},
	{"GET /api/v1/users/{username}/permissions", "GetUserPermissionsHandler"},
	{"POST /api/v1/users/{username}/permissions", "SetUserPermissionsHandler"},
	{"POST /api/v1/users/{username}/permissions/all", "SetUserPermissionsAllHandler"},
	{"POST /api/v1/users/{username}/token/refresh", "RefreshUserTokenHandler"},
	{"DELETE /api/v1/users/{username}/token", "DeleteUserTokenHandler"},
	{"POST /api/v1/users/{username}/{action}", "UserActionHandler"},
	// settings
	{"GET /api/v1/settings", "SettingsHandler"},
	{"GET /api/v1/settings/{service}", "SettingsServiceHandler"},
	{"GET /api/v1/settings/{service}/{env}", "SettingsServiceEnvHandler"},
	{"PATCH /api/v1/settings/{service}/{name}", "SettingPatchHandler"},
	// alerts
	{"GET /api/v1/alerts/rules", "AlertRulesListHandler"},
	{"GET /api/v1/alerts/rules/{id}", "AlertRuleGetHandler"},
	{"POST /api/v1/alerts/rules", "AlertRulesCreateHandler"},
	{"PUT /api/v1/alerts/rules/{id}", "AlertRulesUpdateHandler"},
	{"DELETE /api/v1/alerts/rules/{id}", "AlertRulesDeleteHandler"},
	{"GET /api/v1/alerts/channels", "AlertChannelsListHandler"},
	{"GET /api/v1/alerts/channels/types", "AlertChannelsTypesHandler"},
	{"GET /api/v1/alerts/channels/{id}", "AlertChannelsGetHandler"},
	{"POST /api/v1/alerts/channels", "AlertChannelsCreateHandler"},
	{"POST /api/v1/alerts/channels/test", "AlertChannelsTestHandler"},
	{"PUT /api/v1/alerts/channels/{id}", "AlertChannelsUpdateHandler"},
	{"DELETE /api/v1/alerts/channels/{id}", "AlertChannelsDeleteHandler"},
	{"GET /api/v1/alerts/history", "AlertHistoryHandler"},
	{"POST /api/v1/alerts/apply", "AlertsApplyHandler"},
	// carves
	{"POST /api/v1/carves/{env}/{action}/{name}", "CarvesActionHandler"},
	// audit logs
	{"GET /api/v1/audit-logs", "AuditLogsHandler"},
}

func TestParityRigRunsSameCommandBothModes(t *testing.T) {
	rig := newParityRig(t)
	devEnv, err := rig.Envs.Get("dev")
	require.NoError(t, err)
	// Twice each, interleaved: the command tree is reusable across runs.
	for _, mode := range []string{"db", "api", "db", "api"} {
		run := map[string]func(...string) (string, error){"db": rig.RunDB, "api": rig.RunAPI}[mode]
		out, err := run("env", "list")
		require.NoError(t, err, mode)
		require.Contains(t, out, "dev", mode)
		require.Contains(t, out, devEnv.UUID, mode)
	}
	// Globals are put back after every run.
	require.Nil(t, envs)
	require.Nil(t, osctrlAPI)

	// The API side authenticates per token: a user with no environment access
	// sees none, and an unknown token is rejected.
	out, err := rig.RunAPIAs(rig.SeedUser("bob", false), "env", "list")
	require.NoError(t, err)
	require.Contains(t, out, "No environments")
	_, err = rig.RunAPIAs("bogus", "env", "list")
	require.ErrorContains(t, err, "unauthorized")
}

// withProbeCommand adds a top-level command to the real tree for one test.
func withProbeCommand(t *testing.T, c *cli.Command) {
	t.Helper()
	old := commands
	t.Cleanup(func() { commands = old })
	commands = append(append([]*cli.Command{}, old...), c)
}

func TestParityRigRestoresStdoutOnPanic(t *testing.T) {
	rig := newParityRig(t)
	withProbeCommand(t, &cli.Command{Name: "boom", Action: cliWrapper(func(context.Context, *cli.Command) error {
		panic("boom")
	})})
	stdout := os.Stdout
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		require.PanicsWithValue(t, "boom", func() { _, _ = run("boom") })
		require.Same(t, stdout, os.Stdout)
		require.Nil(t, envs)
		require.Nil(t, osctrlAPI)
	}
}

// env list prints a table whatever the format, so a probe records what the
// action sees: global flags given to one run must not reach the next one.
func TestParityRigFlagStateDoesNotLeak(t *testing.T) {
	rig := newParityRig(t)
	var format string
	var silent bool
	withProbeCommand(t, &cli.Command{Name: "probe", Action: cliWrapper(func(context.Context, *cli.Command) error {
		format, silent = formatFlag, silentFlag
		return nil
	})})
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		_, err := run("-o", "json", "-s", "probe")
		require.NoError(t, err)
		require.Equal(t, jsonFormat, format)
		require.True(t, silent)
		_, err = run("probe")
		require.NoError(t, err)
		require.Equal(t, prettyFormat, format)
		require.False(t, silent)
	}
}

// TestParityRoutesExistInAPI guards parityRoutes against drift: every entry
// must still be registered in cmd/api registerRoutes with the same method,
// path and handler. parityAuth is a copy of the JWT branch of handlerAuthCheck
// (cmd/api/auth.go) and is not covered: re-check it by hand when that changes.
func TestParityRoutesExistInAPI(t *testing.T) {
	consts := map[string]string{}
	files, err := filepath.Glob("../api/*.go")
	require.NoError(t, err)
	constRe := regexp.MustCompile(`(?m)^\s*(\w+)\s*(?:string\s*)?=\s*"([^"]*)"`)
	var mainSrc string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, m := range constRe.FindAllStringSubmatch(string(src), -1) {
			consts[m[1]] = m[2]
		}
		if filepath.Base(f) == "main.go" {
			mainSrc = string(src)
		}
	}
	require.NotEmpty(t, mainSrc)
	// "METHOD "+_apiPath(constPath[+"inner"])[+"suffix"], <wrappers>(handlersApi.Handler
	routeRe := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) "\s*\+\s*_apiPath\((\w+)(?:\s*\+\s*"([^"]*)")?\)(?:\s*\+\s*"([^"]*)")?\s*,[\s\w.(]*?handlersApi\.(\w+)`)
	registered := map[string]bool{}
	for _, m := range routeRe.FindAllStringSubmatch(mainSrc, -1) {
		base, ok := consts[m[2]]
		require.True(t, ok, "unknown path constant %s", m[2])
		registered[m[1]+" "+consts["apiPrefixPath"]+consts["apiVersionPath"]+base+m[3]+m[4]+" "+m[5]] = true
	}
	require.Greater(t, len(registered), 100, "route extraction from cmd/api/main.go broke")
	require.True(t, registered["GET /api/v1/environments/{env} EnvironmentHandler"])
	require.False(t, registered["GET /api/v1/environments/{env} EnvironmentsHandler"], "a wrong handler must not match")
	for _, rt := range parityRoutes {
		require.True(t, registered[rt.pattern+" "+rt.handler], "parity route %q -> %s is not registered in cmd/api/main.go", rt.pattern, rt.handler)
	}
}

// TestAuditLogsParity checks `audit-logs` lists the same entries in both modes
// (the API returns a paged envelope that the client must unwrap).
func TestAuditLogsParity(t *testing.T) {
	rig := newParityRig(t)
	audit, err := auditlog.CreateAuditLogManager(rig.DB, "osctrl-cli", true)
	require.NoError(t, err)
	require.NoError(t, audit.CreateNew("admin", "parity-marker-line", "1.2.3.4", auditlog.LogTypeVisit, auditlog.SeverityInfo, 0))
	for _, mode := range []string{"db", "api"} {
		run := map[string]func(...string) (string, error){"db": rig.RunDB, "api": rig.RunAPI}[mode]
		out, err := run("-o", "json", "audit-logs")
		require.NoError(t, err, mode)
		require.Contains(t, out, "parity-marker-line", mode)
	}
}
