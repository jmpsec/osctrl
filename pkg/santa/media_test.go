package santa

import (
	"testing"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestValidateConfigMedia(t *testing.T) {
	tests := []struct {
		name               string
		cfg                EnvConfig
		wantErr            bool
		wantMedia          string
		wantFlags, wantEnc []string
		wantBlock          bool
	}{
		{"empty is allow", EnvConfig{}, false, MediaAllow, nil, nil, false},
		{"block", EnvConfig{RemovableMedia: MediaBlock}, false, MediaBlock, nil, nil, true},
		{"remount normalizes flags", EnvConfig{RemovableMedia: MediaRemount, RemovableMediaFlags: []string{"RDONLY", " noexec", "rdonly"}},
			false, MediaRemount, []string{"rdonly", "noexec"}, nil, true},
		{"remount accepts -j and async", EnvConfig{RemovableMedia: MediaRemount, RemovableMediaFlags: []string{"-j", "async"}},
			false, MediaRemount, []string{"-j", "async"}, nil, true},
		{"remount without flags", EnvConfig{RemovableMedia: MediaRemount}, true, "", nil, nil, false},
		{"unknown flag", EnvConfig{RemovableMedia: MediaRemount, RemovableMediaFlags: []string{"rw"}}, true, "", nil, nil, false},
		{"flags with block", EnvConfig{RemovableMedia: MediaBlock, RemovableMediaFlags: []string{"rdonly"}}, true, "", nil, nil, false},
		{"unknown action", EnvConfig{RemovableMedia: "DENY"}, true, "", nil, nil, false},
		{"encrypted inherits", EnvConfig{RemovableMedia: MediaBlock, EncryptedRemovableMedia: ""}, false, MediaBlock, nil, nil, true},
		{"encrypted remount", EnvConfig{EncryptedRemovableMedia: MediaRemount, EncryptedRemovableMediaFlags: []string{"rdonly"}},
			false, MediaAllow, nil, []string{"rdonly"}, false},
		{"encrypted flags without action", EnvConfig{EncryptedRemovableMediaFlags: []string{"rdonly"}}, true, "", nil, nil, false},
		{"encrypted unknown action", EnvConfig{EncryptedRemovableMedia: "DENY"}, true, "", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.cfg
			c.ClientMode = "MONITOR"
			err := ValidateConfig(&c)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantMedia, c.RemovableMedia)
			require.Equal(t, tt.wantFlags, c.RemovableMediaFlags)
			require.Equal(t, tt.wantEnc, c.EncryptedRemovableMediaFlags)
			require.Equal(t, tt.wantBlock, c.BlockUSBMount)
		})
	}
}

func TestPreflightRemovableMedia(t *testing.T) {
	tests := []struct {
		name        string
		cfg         EnvConfig
		check       func(t *testing.T, p *syncv1.RemovableMediaPolicy)
		wantEnc     bool
		wantBlock   bool
		wantRemount []string
	}{
		{"allow", EnvConfig{RemovableMedia: MediaAllow},
			func(t *testing.T, p *syncv1.RemovableMediaPolicy) { require.True(t, p.GetAllow()) }, false, false, nil},
		{"block", EnvConfig{RemovableMedia: MediaBlock},
			func(t *testing.T, p *syncv1.RemovableMediaPolicy) { require.True(t, p.GetBlock()) }, false, true, nil},
		{"remount", EnvConfig{RemovableMedia: MediaRemount, RemovableMediaFlags: []string{"rdonly", "noexec"}},
			func(t *testing.T, p *syncv1.RemovableMediaPolicy) {
				require.Equal(t, []string{"rdonly", "noexec"}, p.GetRemount().GetFlags())
			}, false, true, []string{"rdonly", "noexec"}},
		{"encrypted override", EnvConfig{RemovableMedia: MediaBlock, EncryptedRemovableMedia: MediaAllow},
			func(t *testing.T, p *syncv1.RemovableMediaPolicy) { require.True(t, p.GetBlock()) }, true, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t)
			cfg := tt.cfg
			cfg.EnvironmentID, cfg.ClientMode = 1, "MONITOR"
			require.NoError(t, m.SaveConfig(cfg))
			resp := mustPreflight(t, m, testNode(), false)
			require.NotNil(t, resp.RemovableMediaPolicy)
			tt.check(t, resp.GetRemovableMediaPolicy())
			require.Equal(t, tt.wantEnc, resp.EncryptedRemovableMediaPolicy != nil)
			if tt.wantEnc {
				require.True(t, resp.GetEncryptedRemovableMediaPolicy().GetAllow())
			}
			require.NotNil(t, resp.BlockUsbMount)                 //nolint:staticcheck // deprecated, for older clients
			require.Equal(t, tt.wantBlock, *resp.BlockUsbMount)   //nolint:staticcheck // deprecated, for older clients
			require.Equal(t, tt.wantRemount, resp.RemountUsbMode) //nolint:staticcheck // deprecated, for older clients
		})
	}
}

func TestMigrateBackfillsRemovableMedia(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&EnvConfig{}))
	// Rows as saved before removable_media existed.
	require.NoError(t, db.Exec("INSERT INTO santa_env_configs (environment_id, client_mode, block_usb_mount, removable_media) VALUES (1, 'MONITOR', true, ''), (2, 'MONITOR', false, NULL), (3, 'MONITOR', true, 'REMOUNT')").Error)
	require.NoError(t, Migrate(db))
	m := &Manager{DB: db}
	for env, want := range map[uint]string{1: MediaBlock, 2: MediaAllow, 3: MediaRemount} {
		c, err := m.Config(env)
		require.NoError(t, err)
		require.Equal(t, want, c.RemovableMedia, "env %d", env)
	}
}
