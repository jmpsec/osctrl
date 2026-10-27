package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func postUserAction(t *testing.T, h *HandlersApi, caller, username, action string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body["username"] = username
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+username+"/"+action, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("username", username)
	req.SetPathValue("action", action)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	h.UserActionHandler(rr, req)
	return rr
}

// Demoting through user edit (not_admin) applies the permissions endpoints'
// lockout policy (users.CheckLockout). The last-super-admin refusal cannot be
// reached here: the caller must be a global admin, so a different target never
// leaves zero admins; it is covered by the CLI DB tests.
func TestUserEditDemotionLockout(t *testing.T) {
	t.Run("self-demote 403", func(t *testing.T) {
		h := setupUserAdd(t)
		require.NoError(t, h.Users.Create(users.AdminUser{Username: "root2", Admin: true}))
		rr := postUserAction(t, h, "root", "root", users.ActionEdit, map[string]any{"not_admin": true, "email": "new@example.com"})
		require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
		require.Contains(t, rr.Body.String(), "super-admins cannot self-demote")
		u, err := h.Users.Get("root")
		require.NoError(t, err)
		require.True(t, u.Admin)
		require.Empty(t, u.Email, "nothing is written when the demotion is refused")
	})
	t.Run("other admin while another remains", func(t *testing.T) {
		h := setupUserAdd(t)
		require.NoError(t, h.Users.Create(users.AdminUser{Username: "root2", Admin: true}))
		rr := postUserAction(t, h, "root", "root2", users.ActionEdit, map[string]any{"not_admin": true})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.False(t, h.Users.IsAdmin("root2"))
	})
	t.Run("promotion unaffected", func(t *testing.T) {
		h := setupUserAdd(t)
		rr := postUserAction(t, h, "root", "bob", users.ActionEdit, map[string]any{"admin": true})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.True(t, h.Users.IsAdmin("bob"))
	})
}
