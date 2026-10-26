package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/stretchr/testify/require"
)

func TestGetAlertRulesCarriesEnvFilterAndNewFields(t *testing.T) {
	mux := http.NewServeMux()
	var gotEnv string
	mux.HandleFunc("GET /api/v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		gotEnv = r.URL.Query().Get("env")
		_, _ = w.Write([]byte(`[{"id":1,"name":"r","node_uuid":"u-1","vuln_min_severity":"high","status_severity":"error"}]`))
	})
	api := newRealURLServer(t, mux)
	rules, err := api.GetAlertRules(nil)
	require.NoError(t, err)
	require.Empty(t, gotEnv)
	require.Equal(t, "u-1", rules[0].NodeUUID)
	require.Equal(t, "high", rules[0].VulnMinSeverity)
	env := uint(3)
	_, err = api.GetAlertRules(&env)
	require.NoError(t, err)
	require.Equal(t, "3", gotEnv)
	zero := uint(0)
	_, err = api.GetAlertRules(&zero)
	require.NoError(t, err)
	require.Equal(t, "0", gotEnv)
}

func TestCreateAlertRuleSendsNodeAndVulnSeverity(t *testing.T) {
	mux := http.NewServeMux()
	var got map[string]any
	mux.HandleFunc("POST /api/v1/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	require.NoError(t, api.CreateAlertRule(alerts.AlertRule{
		Name: "r", Source: "vuln_finding", MatchType: "substring", MatchValue: "x", EnvironmentID: 2,
		NodeUUID: "u-1", VulnMinSeverity: "kev", StatusSeverity: "error", Info: "i",
	}))
	require.Equal(t, "u-1", got["node_uuid"])
	require.Equal(t, "kev", got["vuln_min_severity"])
	require.Equal(t, "error", got["status_severity"])
	require.EqualValues(t, 2, got["environment_id"])
	require.Equal(t, "i", got["info"])
}
