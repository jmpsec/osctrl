package main

import (
	"context"
	"testing"

	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/stretchr/testify/require"
)

func tagSensitive(t *testing.T, r *parityRig, envUUID, name string) bool {
	t.Helper()
	tg, err := tags.CreateTagManager(r.DB).Get(name, mustEnvID(t, r, envUUID))
	require.NoError(t, err)
	return tg.Sensitive
}

func mustEnvID(t *testing.T, r *parityRig, uuid string) uint {
	t.Helper()
	e, err := r.Envs.Get(uuid)
	require.NoError(t, err)
	return e.ID
}

func TestTagSensitiveFlagBothModes(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	for mode, run := range r.modes() {
		secret, web := "secret-"+mode, "web-"+mode
		_, err := run("tag", "add", "-e", env.UUID, "-n", secret, "-C", "x", "--sensitive")
		require.NoError(t, err, mode)
		require.True(t, tagSensitive(t, r, env.UUID, secret), mode)
		_, err = run("tag", "add", "-e", env.UUID, "-n", web, "-C", "x")
		require.NoError(t, err, mode)
		require.False(t, tagSensitive(t, r, env.UUID, web), mode)

		for _, c := range []struct {
			args []string
			want bool
		}{
			{[]string{"--sensitive"}, true},
			{[]string{"-d", "changed"}, true}, // flag omitted: unchanged
			{[]string{"--sensitive=false"}, false},
		} {
			_, err = run(append([]string{"tag", "edit", "-e", env.UUID, "-n", web}, c.args...)...)
			require.NoError(t, err, mode)
			require.Equal(t, c.want, tagSensitive(t, r, env.UUID, web), mode, c.args)
		}

		out, err := run("-o", "json", "tag", "list", "-e", env.UUID)
		require.NoError(t, err, mode)
		require.Contains(t, out, `"sensitive":true`, mode)
		out, err = run("-o", "csv", "tag", "list", "-e", env.UUID)
		require.NoError(t, err, mode)
		require.Contains(t, out, "Sensitive", mode)
		out, err = run("tag", "show", "-e", env.UUID, "-n", secret)
		require.NoError(t, err, mode)
		require.Contains(t, out, "Sensitive: True", mode)
	}
}

func TestTagEditSensitiveRemovesScopeGrantBothModes(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	r.SeedUser("bob", false)
	for mode, run := range r.modes() {
		name := "web-" + mode
		_, err = run("tag", "add", "-e", env.UUID, "-n", name, "-C", "x")
		require.NoError(t, err, mode)
		tg, err := tags.CreateTagManager(r.DB).Get(name, env.ID)
		require.NoError(t, err, mode)
		require.NoError(t, r.Users.SetScopeTags("bob", env.UUID, "admin", []uint{tg.ID}), mode)
		ids, err := r.Users.ScopeTagIDsContext(context.Background(), "bob", env.UUID)
		require.NoError(t, err, mode)
		require.Equal(t, []uint{tg.ID}, ids, mode)

		_, err = run("tag", "edit", "-e", env.UUID, "-n", name, "--sensitive")
		require.NoError(t, err, mode)
		ids, err = r.Users.ScopeTagIDsContext(context.Background(), "bob", env.UUID)
		require.NoError(t, err, mode)
		require.Empty(t, ids, mode)
	}
}

func TestTagEditKeepsNonCanonicalCustomBothModes(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	mgr := tags.CreateTagManager(r.DB)
	for mode, run := range r.modes() {
		name := "web-" + mode
		_, err := run("tag", "add", "-e", env.UUID, "-n", name, "-C", "x")
		require.NoError(t, err, mode)
		require.NoError(t, r.DB.Model(&tags.AdminTag{}).Where("name = ? AND environment_id = ?", name, env.ID).Update("custom_tag", "Legacy-Value").Error, mode)
		_, err = run("tag", "edit", "-e", env.UUID, "-n", name, "--sensitive")
		require.NoError(t, err, mode)
		got, err := mgr.Get(name, env.ID)
		require.NoError(t, err, mode)
		require.Equal(t, "Legacy-Value", got.CustomTag, mode)
	}
}

func TestTagEditKeepsUnsetFieldsBothModes(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	mgr := tags.CreateTagManager(r.DB)
	for mode, run := range r.modes() {
		name := "web-" + mode
		_, err := run("tag", "add", "-e", env.UUID, "-n", name, "-t", "custom", "-C", "role", "-c", "#112233", "-i", "bolt", "-d", "orig")
		require.NoError(t, err, mode)
		before, err := mgr.Get(name, env.ID)
		require.NoError(t, err)
		for _, args := range [][]string{{"--sensitive"}, {"-d", "newdesc"}} {
			_, err = run(append([]string{"tag", "edit", "-e", env.UUID, "-n", name}, args...)...)
			require.NoError(t, err, mode)
			got, err := mgr.Get(name, env.ID)
			require.NoError(t, err)
			require.Equal(t, before.TagType, got.TagType, mode, args)
			require.Equal(t, before.CustomTag, got.CustomTag, mode, args)
			require.Equal(t, before.Color, got.Color, mode, args)
			require.Equal(t, before.Icon, got.Icon, mode, args)
			if args[0] == "--sensitive" {
				require.Equal(t, before.Description, got.Description, mode)
				require.True(t, got.Sensitive, mode)
			} else {
				require.Equal(t, "newdesc", got.Description, mode)
			}
		}
	}
}
