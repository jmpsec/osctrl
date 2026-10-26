package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestGetUserPermissions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/users/{username}/permissions", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer testtoken", r.Header.Get("Authorization"))
		if r.PathValue("username") == "ghost" {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(types.GetPermissionsResponse{
			Username:    r.PathValue("username"),
			Permissions: map[string]types.EnvAccessView{"uuid-1": {User: true, Admin: true}},
		})
	})
	api := newRealURLServer(t, mux)
	resp, err := api.GetUserPermissions("bob")
	require.NoError(t, err)
	require.Equal(t, "bob", resp.Username)
	require.Equal(t, types.EnvAccessView{User: true, Admin: true}, resp.Permissions["uuid-1"])
	_, err = api.GetUserPermissions("ghost")
	require.ErrorContains(t, err, "404")
	require.ErrorContains(t, err, "user not found")
}

func TestSetUserPermissions(t *testing.T) {
	mux := http.NewServeMux()
	var got types.SetPermissionsRequest
	mux.HandleFunc("POST /api/v1/users/{username}/permissions", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("username") == "root" {
			http.Error(w, `{"error":"refusing to demote the last super-admin"}`, http.StatusConflict)
			return
		}
		require.Equal(t, "bob", r.PathValue("username"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	require.NoError(t, api.SetUserPermissions("bob", "uuid-1", users.EnvAccess{User: true, Carve: true}))
	require.Equal(t, types.SetPermissionsRequest{EnvUUID: "uuid-1", Access: types.EnvAccessView{User: true, Carve: true}}, got)
	err := api.SetUserPermissions("root", "uuid-1", users.EnvAccess{})
	require.ErrorContains(t, err, "409")
	require.ErrorContains(t, err, "last super-admin")
}

func TestPermissionsEscapeUsername(t *testing.T) {
	mux := http.NewServeMux()
	var got string
	mux.HandleFunc("GET /api/v1/users/{username}/permissions", func(w http.ResponseWriter, r *http.Request) {
		got = r.PathValue("username")
		_, _ = w.Write([]byte(`{"permissions":{}}`))
	})
	api := newRealURLServer(t, mux)
	_, err := api.GetUserPermissions("a b/c")
	require.NoError(t, err)
	require.Equal(t, "a b/c", got)
}
