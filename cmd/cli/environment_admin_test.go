package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// withStdin makes os.Stdin read input (then EOF) until the test ends.
func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = r.Close() })
}

// testCertFile writes a self-signed PEM certificate and returns its path and contents.
func testCertFile(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "osctrl"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	file := filepath.Join(t.TempDir(), "osctrl.crt")
	require.NoError(t, os.WriteFile(file, []byte(certPEM), 0o600))
	return file, certPEM
}

// requireFlags compares flagfiles ignoring surrounding whitespace, which the
// API's config PATCH trims.
func requireFlags(t *testing.T, want, got string, msg string) {
	t.Helper()
	require.Equal(t, strings.TrimSpace(want), strings.TrimSpace(got), msg)
}

func (r *parityRig) runner(mode string) func(...string) (string, error) {
	return map[string]func(...string) (string, error){"db": r.RunDB, "api": r.RunAPI}[mode]
}

func (r *parityRig) env(name string) environments.TLSEnvironment {
	r.t.Helper()
	env, err := r.Envs.Get(name)
	require.NoError(r.t, err)
	return env
}

// TestEnvAddParity creates one environment per mode with the same flags and
// compares what is stored.
//
// Intentional DB-vs-API differences (not compared):
//   - tag colour: random in both modes; tag CreatedBy is "osctrl-cli" in DB
//     mode and the API user in API mode.
//   - API mode grants the creating user full access to the new environment;
//     DB mode grants nothing.
//   - audit lines: "add environment <name>" (DB) vs the API's "create env
//     <name>", "config patch on env <name>", link and certificate lines.
//   - link expiry: both are now + DefaultLinkExpire hours, set at different
//     instants (compared within a tolerance).
//   - API mode lowercases the name and validates name/hostname filters and
//     the certificate (x509); DB mode stores them as given.
//   - UUID, secret, secret paths: random per environment.
//   - stored flags: the API's config PATCH trims surrounding whitespace, so
//     API-mode flags lack the leading and trailing newlines the generated
//     template has (requireFlags ignores them). Same for update and new-flags.
func TestEnvAddParity(t *testing.T) {
	rig := newParityRig(t)
	certFile, certPEM := testCertFile(t)
	want := time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
	tm := tags.CreateTagManager(rig.DB)
	stored := map[string]environments.TLSEnvironment{}
	for _, mode := range []string{"db", "api"} {
		name := "add-" + mode
		out, err := rig.runner(mode)("env", "add", "-n", name, "--host", name+".example.com", "-d", "--crt", certFile, "--carve=false")
		require.NoError(t, err, mode)
		require.Contains(t, out, "was created successfully", mode)
		env := rig.env(name)
		stored[mode] = env
		require.Equal(t, name+".example.com", env.Hostname, mode)
		require.True(t, env.DebugHTTP, mode)
		require.True(t, env.AcceptEnrolls, mode)
		require.Equal(t, certPEM, env.Certificate, mode)
		require.WithinDuration(t, want, env.EnrollExpire, 5*time.Minute, mode)
		require.WithinDuration(t, want, env.RemoveExpire, 5*time.Minute, mode)
		flags, err := rig.Envs.GenerateFlags(env, "", "", config.YAMLConfigurationOsquery{Config: true, Logger: true, Query: true})
		require.NoError(t, err)
		requireFlags(t, flags, env.Flags, mode)
		require.Contains(t, env.Flags, "--tls_server_certs", mode)
		require.True(t, tm.ExistsByEnv(name, env.ID), mode)
		tag, err := tm.Get(name, env.ID)
		require.NoError(t, err)
		require.Equal(t, tags.TagTypeEnv, tag.TagType, mode)
		require.Equal(t, tags.TagCustomEnv, tag.CustomTag, mode)

		// Exists already: an error, not os.Exit.
		_, err = rig.runner(mode)("env", "add", "-n", name, "--host", name+".example.com")
		require.ErrorContains(t, err, "already exists", mode)
	}
	db, api := stored["db"], stored["api"]
	for field, pair := range map[string][2]interface{}{
		"Type":          {db.Type, api.Type},
		"Icon":          {db.Icon, api.Icon},
		"Options":       {db.Options, api.Options},
		"Schedule":      {db.Schedule, api.Schedule},
		"Packs":         {db.Packs, api.Packs},
		"Decorators":    {db.Decorators, api.Decorators},
		"ATC":           {db.ATC, api.ATC},
		"Configuration": {db.Configuration, api.Configuration},
		"Intervals":     {[3]int{db.ConfigInterval, db.LogInterval, db.QueryInterval}, [3]int{api.ConfigInterval, api.LogInterval, api.QueryInterval}},
		"TLS":           {[4]bool{db.ConfigTLS, db.LoggingTLS, db.QueryTLS, db.CarvesTLS}, [4]bool{api.ConfigTLS, api.LoggingTLS, api.QueryTLS, api.CarvesTLS}},
		"Packages":      {db.DebPackage + db.RpmPackage + db.MsiPackage + db.PkgPackage, api.DebPackage + api.RpmPackage + api.MsiPackage + api.PkgPackage},
	} {
		require.Equal(t, pair[0], pair[1], field)
	}
	require.Contains(t, db.Decorators, environments.DecoratorHostname)
	// Flags only differ by the environment's own values.
	requireFlags(t, db.Flags, strings.NewReplacer(api.UUID, db.UUID, api.Hostname, db.Hostname).Replace(api.Flags), "db vs api")
}

func TestEnvAddAPIFollowUpFailureLeavesEnvAndNamesStep(t *testing.T) {
	rig := newParityRig(t)
	bad := filepath.Join(t.TempDir(), "bad.crt")
	require.NoError(t, os.WriteFile(bad, []byte("not a certificate"), 0o600))
	_, err := rig.RunAPI("env", "add", "-n", "half", "--host", "half.example.com", "-d", "--crt", bad)
	require.ErrorContains(t, err, "certificate upload")
	require.ErrorContains(t, err, "environment half was created")
	require.ErrorContains(t, err, "400")
	env := rig.env("half")
	// Steps before the upload ran, steps after it did not.
	require.Contains(t, env.Decorators, environments.DecoratorHostname)
	require.Empty(t, env.Certificate)
	require.False(t, env.DebugHTTP)
}

// Intentional DB-vs-API `env update` differences: the API rejects intervals
// below 1 and invalid hostnames with 400, while DB mode stores them as given
// (API mode rejects negative intervals client-side, before any request).
func TestEnvUpdateOmittedBooleansUnchanged(t *testing.T) {
	rig := newParityRig(t)
	for _, mode := range []string{"db", "api"} {
		name := "upd-" + mode
		rig.SeedEnv(name)
		run := func(args ...string) environments.TLSEnvironment {
			_, err := rig.runner(mode)(append([]string{"env", "update", "-n", name}, args...)...)
			require.NoError(t, err, mode, args)
			return rig.env(name)
		}
		env := run("-d")
		require.True(t, env.DebugHTTP, mode)
		require.True(t, env.AcceptEnrolls, mode)
		env = run("--host", "other.example.com")
		require.Equal(t, "other.example.com", env.Hostname, mode)
		require.True(t, env.DebugHTTP, mode, "omitted --debug keeps it")
		require.True(t, env.AcceptEnrolls, mode, "omitted --enroll keeps it")
		env = run("--debug=false")
		require.False(t, env.DebugHTTP, mode)
		require.True(t, env.AcceptEnrolls, mode)
		env = run("--enroll=false")
		require.False(t, env.AcceptEnrolls, mode)
		require.False(t, env.DebugHTTP, mode)
		env = run("-e")
		require.True(t, env.AcceptEnrolls, mode)
	}
}

// env update regenerates the stored flags when an input the flags encode is
// given (a plugin flag, --hostname, an interval), and leaves them alone for
// --debug, --enroll and package URLs.
func TestEnvUpdateRegeneratesFlagsOnFlagInputs(t *testing.T) {
	rig := newParityRig(t)
	allPlugins := config.YAMLConfigurationOsquery{Config: true, Logger: true, Query: true, Carve: true}
	noCarve := config.YAMLConfigurationOsquery{Config: true, Logger: true, Query: true}
	for _, mode := range []string{"db", "api"} {
		for _, c := range []struct {
			args  []string
			regen bool
			osq   config.YAMLConfigurationOsquery
		}{
			{[]string{"-d"}, false, allPlugins},
			{[]string{"--enroll=false"}, false, allPlugins},
			{[]string{"--deb", "https://pkg.example.com/o.deb", "--pkg", "https://pkg.example.com/o.pkg"}, false, allPlugins},
			{[]string{"--carve-plugin=false"}, true, noCarve},
			{[]string{"--config-plugin"}, true, allPlugins},
			{[]string{"--host", "new.example.com"}, true, allPlugins},
			{[]string{"-l", "46"}, true, allPlugins},
			{[]string{"-c", "45"}, true, allPlugins},
			{[]string{"-q", "47"}, true, allPlugins},
		} {
			name := "flags-" + mode
			rig.SeedEnv(name)
			require.NoError(t, rig.Envs.UpdateFlags(name, "--custom_flag=1"))
			_, err := rig.runner(mode)(append([]string{"env", "update", "-n", name}, c.args...)...)
			require.NoError(t, err, mode, c.args)
			env := rig.env(name)
			if !c.regen {
				require.Equal(t, "--custom_flag=1", env.Flags, mode, c.args)
			} else {
				flags, err := rig.Envs.GenerateFlags(env, "", "", c.osq)
				require.NoError(t, err)
				requireFlags(t, flags, env.Flags, mode+" "+strings.Join(c.args, " "))
			}
			require.NoError(t, rig.Envs.Delete(name))
		}
	}
}

// What deploy/provision.sh and the docker entrypoint run: the stored flags
// must carry the new intervals afterwards.
func TestEnvUpdateIntervalsRefreshStoredFlags(t *testing.T) {
	rig := newParityRig(t)
	for _, mode := range []string{"db", "api"} {
		name := "iv-" + mode
		rig.SeedEnv(name)
		_, err := rig.runner(mode)("env", "update", "-n", name, "-l", "75", "-c", "45", "-q", "60")
		require.NoError(t, err, mode)
		env := rig.env(name)
		require.Equal(t, [3]int{45, 75, 60}, [3]int{env.ConfigInterval, env.LogInterval, env.QueryInterval}, mode)
		for _, f := range []string{"--config_tls_refresh=45", "--logger_tls_period=75", "--distributed_interval=60"} {
			require.Contains(t, env.Flags, f, mode)
		}
	}
}

func TestConfirmEnvDelete(t *testing.T) {
	for _, c := range []struct {
		input string
		ok    bool
	}{{"dev\n", true}, {"dev\r\n", true}, {"dev", true}, {"Dev\n", false}, {"dev2\n", false}, {"\n", false}, {"", false}, {" dev\n", false}} {
		var out bytes.Buffer
		err := confirmEnvDelete("dev", strings.NewReader(c.input), &out)
		require.Equal(t, c.ok, err == nil, "%q", c.input)
		require.Contains(t, out.String(), "Type the environment name to confirm deletion:")
	}
}

func TestEnvDeleteRequiresConfirmation(t *testing.T) {
	rig := newParityRig(t)
	for _, mode := range []string{"db", "api"} {
		name := "del-" + mode
		rig.SeedEnv(name)
		for _, input := range []string{"wrong\n", "\n", ""} {
			withStdin(t, input)
			_, err := rig.runner(mode)("env", "delete", "-n", name)
			require.ErrorContains(t, err, "not confirmed", mode, input)
			require.True(t, rig.Envs.Exists(name), mode, input)
		}
		withStdin(t, name+"\n")
		_, err := rig.runner(mode)("env", "delete", "-n", name)
		require.NoError(t, err, mode)
		require.False(t, rig.Envs.Exists(name), mode)

		for _, skip := range [][]string{{"env", "delete", "--yes"}, {"env", "delete", "-y"}, {"-s", "env", "delete"}} {
			rig.SeedEnv(name)
			withStdin(t, "")
			_, err := rig.runner(mode)(append(skip, "-n", name)...)
			require.NoError(t, err, mode, skip)
			require.False(t, rig.Envs.Exists(name), mode, skip)
		}
	}
}

func TestEnvNewFlagsParity(t *testing.T) {
	rig := newParityRig(t)
	for _, mode := range []string{"db", "api"} {
		name := "nf-" + mode
		rig.SeedEnv(name)
		require.NoError(t, rig.Envs.UpdateFlags(name, "--custom_flag=1"))
		_, err := rig.runner(mode)("env", "node-actions", "-n", name, "new-flags", "--query=false")
		require.NoError(t, err, mode)
		env := rig.env(name)
		flags, err := rig.Envs.GenerateFlags(env, "", "", config.YAMLConfigurationOsquery{Config: true, Logger: true, Carve: true})
		require.NoError(t, err)
		requireFlags(t, flags, env.Flags, mode)
	}
}

// A token without the permission gets the API's 403 text and nothing changes.
func TestEnvAdminForbiddenShown(t *testing.T) {
	rig := newParityRig(t)
	dev := rig.env("dev")
	bob := rig.SeedUser("bob", false)
	require.NoError(t, rig.Users.SetEnvLevel("bob", dev.UUID, users.UserLevel, true))
	for _, args := range [][]string{
		{"env", "add", "-n", "bobenv", "--host", "bob.example.com"},
		{"env", "update", "-n", "dev", "-d", "--host", "bob.example.com"},
		{"env", "update", "-n", "dev", "-c", "99"},
		{"env", "delete", "-n", "dev", "--yes"},
		{"env", "node-actions", "-n", "dev", "new-flags"},
	} {
		_, err := rig.RunAPIAs(bob, args...)
		require.ErrorContains(t, err, "403", args)
		require.ErrorContains(t, err, "no access", args)
	}
	require.False(t, rig.Envs.Exists("bobenv"))
	after := rig.env("dev")
	require.Equal(t, dev.Hostname, after.Hostname)
	require.Equal(t, dev.DebugHTTP, after.DebugHTTP)
	require.Equal(t, dev.ConfigInterval, after.ConfigInterval)
	require.Equal(t, dev.Flags, after.Flags)
}

// The shell's `environments delete` goes through the store in both modes and
// keeps its own y/N confirmation; the DB store writes an audit line.
func TestShellEnvDeleteUsesStore(t *testing.T) {
	rig := newParityRig(t)
	audit, err := auditlog.CreateAuditLogManager(rig.DB, "osctrl-cli", true)
	require.NoError(t, err)
	envs, auditlogsmgr = rig.Envs, audit // restored by the rig
	for mode, store := range map[string]DataStore{"db": &dbStore{}, "api": &apiStore{api: rig.API}} {
		name := "sh-" + mode
		rig.SeedEnv(name)
		s := &shellState{store: store, rl: &lineEditor{}}
		withStdin(t, "n\n")
		shEnvDelete(s, []string{name})
		require.True(t, rig.Envs.Exists(name), mode)
		s.rl = &lineEditor{}
		withStdin(t, "y\n")
		shEnvDelete(s, []string{name})
		require.False(t, rig.Envs.Exists(name), mode)
	}
	logs, err := audit.GetAll()
	require.NoError(t, err)
	found := false
	for _, l := range logs {
		found = found || (l.Service == "osctrl-cli" && strings.Contains(l.Line, "delete environment sh-db"))
	}
	require.True(t, found, "DB store audits the delete")
}

// A negative interval in API mode fails before the first request, so a
// combined -d is not left applied; env add prints the name the API stored.
func TestEnvUpdateAPINegativeIntervalAppliesNothing(t *testing.T) {
	rig := newParityRig(t)
	rig.SeedEnv("neg")
	_, err := rig.RunAPI("env", "update", "-n", "neg", "-d", "-l", "-5")
	require.Error(t, err)
	require.False(t, rig.env("neg").DebugHTTP, "debug must not be applied")
}

func TestEnvAddAPIPrintsStoredName(t *testing.T) {
	rig := newParityRig(t)
	out, err := rig.RunAPI("env", "add", "-n", "MixedCase", "--host", "mc.example.com")
	require.NoError(t, err)
	require.Contains(t, out, "environment mixedcase was created")
}

// env new-flags and rotate-enroll/rotate-remove write the same audit lines in
// DB mode as the API does for them.
func TestEnvFlagsAndRotateAuditParity(t *testing.T) {
	rig := newParityRig(t)
	lines := map[string][]string{}
	for _, mode := range []string{"db", "api"} {
		name := "aud"
		if mode == "api" {
			name = "aud2"
		}
		rig.SeedEnv(name)
		envAuditRows(t, rig, name)
		for _, a := range []string{"new-flags", "rotate-enroll", "rotate-remove", "extend-enroll", "expire-enroll", "notexpire-enroll", "extend-remove", "expire-remove", "notexpire-remove"} {
			_, err := rig.runner(mode)("env", "node-actions", "-n", name, a)
			require.NoError(t, err, mode, a)
		}
		for _, r := range envAuditRows(t, rig, name) {
			l := r.Line
			if _, rest, ok := strings.Cut(l, " performed "); ok {
				l = rest
			}
			lines[mode] = append(lines[mode], strings.ReplaceAll(l, name, "ENV"))
		}
		sort.Strings(lines[mode])
	}
	require.NotEmpty(t, lines["api"])
	require.Equal(t, lines["api"], lines["db"])
}

// Deleting an environment (CLI DB/API, shell DB/API store) removes every
// user_permissions row on it, so recreating it with the same UUID grants nothing.
func TestEnvDeleteRemovesPermissions(t *testing.T) {
	rig := newParityRig(t)
	audit, err := auditlog.CreateAuditLogManager(rig.DB, "osctrl-cli", true)
	require.NoError(t, err)
	dev := rig.env("dev")
	rig.SeedUser("bob", false)
	full := users.EnvAccess{User: true, Query: true, Carve: true, Admin: true}
	require.NoError(t, rig.Users.ChangeAccess("bob", dev.UUID, full))
	deleters := map[string]func(name string) error{
		"db":  func(n string) error { _, err := rig.RunDB("env", "delete", "-n", n, "--yes"); return err },
		"api": func(n string) error { _, err := rig.RunAPI("env", "delete", "-n", n, "--yes"); return err },
		"shell-db": func(n string) error {
			envs, auditlogsmgr = rig.Envs, audit // restored by the rig
			return (&dbStore{}).DeleteEnvironment(n)
		},
		"shell-api": func(n string) error { return (&apiStore{api: rig.API}).DeleteEnvironment(n) },
	}
	for mode, del := range deleters {
		name := "perm-" + mode
		env := rig.SeedEnv(name)
		require.NoError(t, rig.Users.ChangeAccess("bob", env.UUID, full))
		require.NoError(t, del(name), mode)
		var n int64
		require.NoError(t, rig.DB.Model(&users.UserPermission{}).Where("environment = ?", env.UUID).Count(&n).Error)
		require.Zero(t, n, mode)
		got, err := rig.Users.GetEnvAccess("bob", dev.UUID)
		require.NoError(t, err, mode)
		require.Equal(t, full, got, "other environments untouched (%s)", mode)
		// Recreated with the same UUID: the old grants are not revived.
		again := rig.Envs.Empty(name, name+".example.com")
		again.UUID = env.UUID
		require.NoError(t, rig.Envs.Create(&again))
		require.False(t, rig.Users.CheckPermissions("bob", users.UserLevel, env.UUID), mode)
		require.False(t, rig.Users.CheckPermissions("bob", users.AdminLevel, env.UUID), mode)
	}
}

// An environment name can never equal another environment's UUID: names that
// parse as a UUID are refused on create and rename (API and CLI DB), and the
// actions create refuses a client UUID that is already some environment's name.
func TestEnvNameCannotBeUUID(t *testing.T) {
	rig := newParityRig(t)
	const u = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	do := func(method, path, body string) (int, string) {
		req, err := http.NewRequest(method, rig.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+rig.AdminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	code, body := do(http.MethodPost, "/api/v1/environments", `{"name":"`+u+`","hostname":"h.example.com","type":"osquery","icon":"server"}`)
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = do(http.MethodPost, "/api/v1/environments/actions", `{"action":"create","name":"`+u+`","hostname":"h.example.com","type":"osquery","icon":"server"}`)
	require.Equal(t, http.StatusBadRequest, code, body)
	code, body = do(http.MethodPatch, "/api/v1/environments/dev", `{"name":"`+u+`"}`)
	require.Equal(t, http.StatusBadRequest, code, body)
	for mode, run := range rig.modes() {
		_, err := run("env", "add", "-n", u, "--host", "h.example.com")
		require.Error(t, err, mode)
	}
	require.False(t, rig.Envs.Exists(u))

	// A legacy environment already NAMED u: a new one cannot take UUID u.
	legacy := rig.Envs.Empty("legacy", "l.example.com")
	require.NoError(t, rig.Envs.Create(&legacy))
	require.NoError(t, rig.DB.Model(&environments.TLSEnvironment{}).Where("id = ?", legacy.ID).Update("name", u).Error)
	code, body = do(http.MethodPost, "/api/v1/environments/actions", `{"action":"create","name":"other","uuid":"`+u+`","hostname":"h.example.com","type":"osquery","icon":"server"}`)
	require.Equal(t, http.StatusConflict, code, body)
	require.False(t, rig.Envs.ExistsByName("other"))
	// Unchanged: a fresh UUID still works.
	code, body = do(http.MethodPost, "/api/v1/environments/actions", `{"action":"create","name":"other","uuid":"7ba7b810-9dad-11d1-80b4-00c04fd430c8","hostname":"h.example.com","type":"osquery","icon":"server"}`)
	require.Equal(t, http.StatusOK, code, body)
}

// DB-mode `env add` applies the API's name validation: trimmed and lowercased,
// then NewEnvNameFilter. Invalid names create nothing, in either mode.
func TestEnvAddNameValidationParity(t *testing.T) {
	rig := newParityRig(t)
	for _, bad := range []string{"has space", "bad!name", "dev.x", "9f1b2c3d-4e5f-4a6b-8c7d-0123456789ab"} {
		for _, mode := range []string{"db", "api"} {
			_, err := rig.runner(mode)("env", "add", "-n", bad, "--host", "bad.example.com")
			require.Error(t, err, "%s %q", mode, bad)
			require.False(t, rig.Envs.Exists(bad), "%s %q", mode, bad)
		}
	}
	// Uppercase is normalised like the API does, not rejected.
	out, err := rig.RunDB("env", "add", "-n", " MixedDB ", "--host", "mc.example.com")
	require.NoError(t, err)
	require.Contains(t, out, "environment mixeddb was created")
	require.True(t, rig.Envs.Exists("mixeddb"))
	require.False(t, rig.Envs.Exists("MixedDB"))
	// Existing check still sees the canonical form.
	_, err = rig.RunDB("env", "add", "-n", "MIXEDDB", "--host", "mc.example.com")
	require.ErrorContains(t, err, "already exists")
}
