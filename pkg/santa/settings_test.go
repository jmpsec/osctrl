package santa

import (
	"strings"
	"testing"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/stretchr/testify/require"
)

func TestPreflightV1Settings(t *testing.T) {
	m := newTestManager(t)
	// Defaults are sent explicitly so turning a setting off reaches clients.
	resp := mustPreflight(t, m, testNode(), false)
	require.NotNil(t, resp.EnableBundles)
	require.False(t, resp.GetEnableBundles())
	require.NotNil(t, resp.AllowedPathRegex)
	require.Empty(t, resp.GetAllowedPathRegex())
	require.NotNil(t, resp.BlockedPathRegex)
	require.False(t, resp.HasEventDetailUrl())

	require.NoError(t, m.SaveConfig(EnvConfig{
		EnvironmentID: 1, ClientMode: "MONITOR", EnableBundles: true, EnableAllEventUpload: true, DisableUnknownEventUpload: true,
		AllowedPathRegex: `^/opt/tools/.*`, BlockedPathRegex: `^/Users/[^/]+/Downloads/.*`,
		EventDetailURL: "https://wiki.example.com/santa?sha=%file_sha%", EventDetailText: " More info ",
	}))
	resp = mustPreflight(t, m, testNode(), false)
	require.True(t, resp.GetEnableBundles())
	require.True(t, resp.GetEnableAllEventUpload())
	require.True(t, resp.GetDisableUnknownEventUpload())
	require.Equal(t, `^/opt/tools/.*`, resp.GetAllowedPathRegex())
	require.Equal(t, `^/Users/[^/]+/Downloads/.*`, resp.GetBlockedPathRegex())
	require.Equal(t, "https://wiki.example.com/santa?sha=%file_sha%", resp.GetEventDetailUrl())
	require.Equal(t, "More info", resp.GetEventDetailText())
}

func TestPreflightEventDetailText(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cfg       EnvConfig
		url, text string
		hasText   bool
	}{
		{"approval default label", EnvConfig{ApprovalURL: "https://osctrl.example.com"}, "https://osctrl.example.com/santa/request/env-uuid?sha256=%file_sha%&machine_id=%machine_id%", "Request approval", true},
		{"approval custom label", EnvConfig{ApprovalURL: "https://osctrl.example.com", EventDetailText: "Ask IT"}, "https://osctrl.example.com/santa/request/env-uuid?sha256=%file_sha%&machine_id=%machine_id%", "Ask IT", true},
		{"custom URL wins", EnvConfig{ApprovalURL: "https://osctrl.example.com", EventDetailURL: "https://x.example.com/%file_sha%"}, "https://x.example.com/%file_sha%", "", false},
	} {
		m := newTestManager(t)
		tt.cfg.EnvironmentID, tt.cfg.ClientMode = 1, "MONITOR"
		require.NoError(t, m.SaveConfig(tt.cfg), tt.name)
		n := testNode()
		n.EnvUUID = "env-uuid"
		resp := mustPreflight(t, m, n, false)
		require.Equal(t, tt.url, resp.GetEventDetailUrl(), tt.name)
		require.Equal(t, tt.hasText, resp.HasEventDetailText(), tt.name)
		require.Equal(t, tt.text, resp.GetEventDetailText(), tt.name)
	}
}

func TestValidateV1Settings(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  EnvConfig
	}{
		{"bad allowed regex", EnvConfig{AllowedPathRegex: "^/opt/(tools"}},
		{"bad blocked regex", EnvConfig{BlockedPathRegex: "*"}},
		{"regex newline", EnvConfig{AllowedPathRegex: "^/a\n^/b"}},
		{"regex too long", EnvConfig{BlockedPathRegex: strings.Repeat("a", 1025)}},
		{"http detail URL", EnvConfig{EventDetailURL: "http://x.example.com"}},
		{"relative detail URL", EnvConfig{EventDetailURL: "/santa/%file_sha%"}},
		{"userinfo detail URL", EnvConfig{EventDetailURL: "https://u:p@x.example.com"}},
		{"long detail text", EnvConfig{EventDetailText: strings.Repeat("x", 33)}},
		{"multiline detail text", EnvConfig{EventDetailText: "a\nb"}},
	} {
		tt.cfg.ClientMode = "MONITOR"
		require.Error(t, ValidateConfig(&tt.cfg), tt.name)
	}
	ok := EnvConfig{ClientMode: "MONITOR", AllowedPathRegex: `^/Applications/(Xcode|Safari)\.app/.*$`, EventDetailText: strings.Repeat("é", 32)}
	require.NoError(t, ValidateConfig(&ok))
}

func TestPreflightSyncInterval(t *testing.T) {
	for _, tt := range []struct {
		name    string
		seconds uint32
		ok      bool
	}{
		{"default", 0, true},
		{"minimum", MinSyncInterval, true},
		{"custom", 300, true},
		{"maximum", MaxSyncInterval, true},
		{"below minimum", MinSyncInterval - 1, false},
		{"above maximum", MaxSyncInterval + 1, false},
	} {
		m := newTestManager(t)
		err := m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", FullSyncIntervalSeconds: tt.seconds})
		if !tt.ok {
			require.Error(t, err, tt.name)
			continue
		}
		require.NoError(t, err, tt.name)
		require.Equal(t, tt.seconds, mustPreflight(t, m, testNode(), false).GetFullSyncIntervalSeconds(), tt.name)
	}
}

func TestEventUploadBundles(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	bundle := strings.ToUpper(hexID(0xab))
	blocked := &syncv1.EventUploadRequest{Events: []*syncv1.Event{
		{FileSha256: hexID(1), Decision: syncv1.Decision_BLOCK_UNKNOWN, FileBundleHash: bundle},
		{FileSha256: hexID(2), Decision: syncv1.Decision_BLOCK_UNKNOWN, FileBundleHash: bundle},
		{FileSha256: hexID(3), Decision: syncv1.Decision_BLOCK_UNKNOWN, FileBundleHash: "not-a-hash"},
	}}

	// Bundles off: nothing is asked for.
	resp, err := m.EventUpload(n, blocked)
	require.NoError(t, err)
	require.Empty(t, resp.GetEventUploadBundleBinaries())

	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", EnableBundles: true}))
	resp, err = m.EventUpload(n, blocked)
	require.NoError(t, err)
	require.Equal(t, []string{hexID(0xab)}, resp.GetEventUploadBundleBinaries())

	// Once the bundle's binaries arrive, it is not asked for again.
	resp, err = m.EventUpload(n, &syncv1.EventUploadRequest{Events: []*syncv1.Event{
		{FileSha256: hexID(4), Decision: syncv1.Decision_BUNDLE_BINARY, FileBundleHash: bundle},
	}})
	require.NoError(t, err)
	require.Empty(t, resp.GetEventUploadBundleBinaries())
	resp, err = m.EventUpload(n, blocked)
	require.NoError(t, err)
	require.Empty(t, resp.GetEventUploadBundleBinaries())

	evs, _, err := m.Events(1, 1, 50, EventFilter{})
	require.NoError(t, err)
	var stored []string
	for _, e := range evs {
		if e.Decision == DecisionBundleBinary {
			stored = append(stored, e.BundleHash)
		}
	}
	require.Equal(t, []string{hexID(0xab)}, stored)
}
