package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaRulesChangedMidSyncIs409(t *testing.T) {
	f := newSantaFixture(t)
	require.Equal(t, http.StatusOK, f.post(santaEnvUUID, "preflight", santaMachineID, f.token, []byte(`{}`)).Code)
	require.NoError(t, f.h.Santa.CreateRule(&santa.Rule{EnvironmentID: f.env.ID, RuleType: "BINARY", Identifier: strings.Repeat("ab", 32), Policy: "BLOCKLIST", Scope: "env"}))
	w := f.post(santaEnvUUID, "ruledownload", santaMachineID, f.token, []byte(`{}`))
	require.Equal(t, http.StatusConflict, w.Code)
	require.Empty(t, w.Body.String())
}
