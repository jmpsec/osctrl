package apiclient

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type inactivityTransport func(*http.Request) (*http.Response, error)

func (f inactivityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGetEnvironmentInactiveHours(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
		want   int64
	}{
		{"override", `{"override_hours":2,"inactive_hours":2,"source":"environment"}`, 200, 2},
		{"inherited", `{"override_hours":null,"inactive_hours":168,"source":"global"}`, 200, 168},
		{"maximum", `{"inactive_hours":2562047}`, 200, 2562047},
		{"missing", `{}`, 200, 0},
		{"zero", `{"inactive_hours":0}`, 200, 0},
		{"negative", `{"inactive_hours":-1}`, 200, 0},
		{"overflow", `{"inactive_hours":2562048}`, 200, 0},
		{"fraction", `{"inactive_hours":2.5}`, 200, 0},
		{"invalid JSON", `not JSON`, 200, 0},
		{"forbidden", `{"error":"forbidden"}`, 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, err := CreateAPIWithTransport(JSONConfigurationAPI{URL: "http://osctrl.test", Token: "test"}, inactivityTransport(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/api/v1/environments/inactive-hours/dev%20fleet", r.URL.EscapedPath())
				require.Equal(t, "Bearer test", r.Header.Get("Authorization"))
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			require.NoError(t, err)
			got, err := api.GetEnvironmentInactiveHours("dev fleet")
			if tc.want == 0 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, got)
		})
	}
}
