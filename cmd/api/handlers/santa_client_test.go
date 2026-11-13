package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

// The Santa methods of pkg/apiclient are what the MCP tools call. This runs
// them against the real handlers on the real route patterns, so a drift in a
// path, query parameter or JSON shape fails here.
func TestSantaAPIClientRoundTrip(t *testing.T) {
	h, db, envA, _ := setupSantaHandlers(t)
	as := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r.WithContext(context.WithValue(r.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"})))
		})
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/santa/{env}/rules", as(h.SantaRulesHandler))
	mux.Handle("POST /api/v1/santa/{env}/rules", as(h.SantaRuleCreateHandler))
	mux.Handle("DELETE /api/v1/santa/{env}/rules/{id}", as(h.SantaRuleDeleteHandler))
	mux.Handle("GET /api/v1/santa/{env}/machines", as(h.SantaMachinesHandler))
	mux.Handle("GET /api/v1/santa/{env}/machines/{machineid}/rules", as(h.SantaEffectiveRulesHandler))
	mux.Handle("GET /api/v1/santa/{env}/events", as(h.SantaEventsHandler))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	api, err := apiclient.CreateAPIWithTransport(apiclient.JSONConfigurationAPI{URL: srv.URL}, http.DefaultTransport)
	require.NoError(t, err)

	uuid := "22222222-2222-4222-8222-222222222222"
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: strings.ToUpper(uuid), EnvironmentID: envA.ID}).Error)
	require.NoError(t, h.Santa.SaveMachine(&santa.Machine{EnvironmentID: envA.ID, MachineID: strings.ToUpper(uuid), Hostname: "mac-01"}))
	require.NoError(t, h.Santa.AddEvents([]santa.Event{
		{EnvironmentID: envA.ID, MachineID: strings.ToUpper(uuid), Decision: "BLOCK_BINARY", FilePath: "/tmp/a b&c"},
		{EnvironmentID: envA.ID, MachineID: "OTHER", Decision: "ALLOW_BINARY"},
	}))

	rule, err := api.CreateSantaRule(envA.Name, santa.RuleSpec{RuleType: "TEAMID", Identifier: "EQHXZ8M8AV", Policy: "ALLOWLIST", Scope: "env"})
	require.NoError(t, err)
	require.NotZero(t, rule.ID)
	require.Equal(t, "alice", rule.CreatedBy)
	_, err = api.CreateSantaRule(envA.Name, santa.RuleSpec{RuleType: "TEAMID", Identifier: "bad", Policy: "ALLOWLIST", Scope: "env"})
	require.ErrorContains(t, err, "invalid rule")

	machines, err := api.GetSantaMachines(envA.Name)
	require.NoError(t, err)
	require.Len(t, machines, 1)
	require.Equal(t, "mac-01", machines[0].Hostname)

	eff, err := api.GetSantaEffectiveRules(envA.Name, uuid)
	require.NoError(t, err)
	require.Len(t, eff.Rules, 1)
	require.Equal(t, "env", eff.ModeSource)
	_, err = api.GetSantaEffectiveRules(envA.Name, "44444444-4444-4444-8444-444444444444")
	require.ErrorContains(t, err, "404")

	evs, err := api.GetSantaEvents(envA.Name, santa.EventFilter{MachineID: uuid, Decision: "block"}, 1, 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, evs.Total)
	require.Equal(t, "/tmp/a b&c", evs.Events[0].FilePath)
	all, err := api.GetSantaEvents(envA.Name, santa.EventFilter{}, 1, 10)
	require.NoError(t, err)
	require.EqualValues(t, 2, all.Total)
	_, err = api.GetSantaEvents(envA.Name, santa.EventFilter{Decision: "BLOCK%"}, 1, 10)
	require.ErrorContains(t, err, "400")

	require.NoError(t, api.DeleteSantaRule(envA.Name, rule.ID))
	require.ErrorContains(t, api.DeleteSantaRule(envA.Name, rule.ID), "404")
	rules, err := api.GetSantaRules(envA.Name)
	require.NoError(t, err)
	require.Empty(t, rules)

	// carol is not an environment admin: the same client call is refused.
	denied := http.NewServeMux()
	denied.Handle("GET /api/v1/santa/{env}/events", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.SantaEventsHandler(w, r.WithContext(context.WithValue(r.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "carol"})))
	}))
	srv2 := httptest.NewServer(denied)
	defer srv2.Close()
	api2, err := apiclient.CreateAPIWithTransport(apiclient.JSONConfigurationAPI{URL: srv2.URL}, http.DefaultTransport)
	require.NoError(t, err)
	_, err = api2.GetSantaEvents(envA.Name, santa.EventFilter{}, 1, 10)
	require.ErrorContains(t, err, "403")
}
