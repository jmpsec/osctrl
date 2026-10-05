package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEventsAuthErrorsAreJSON(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/events?env=dev&topic=queries", nil)
	r.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()
	handlerAuthCheck(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated stream admitted") }), config.AuthJWT, "event-test-secret-at-least-thirty-two-bytes").ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Empty(t, w.Header().Get("Location"))
	require.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestEventSessionRechecksStoredTokenAndIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	previous := apiUsers
	t.Cleanup(func() { apiUsers = previous })
	apiUsers = users.CreateUserManager(db).WithJWT(&config.YAMLConfigurationJWT{JWTSecret: "event-test-secret-at-least-thirty-two-bytes", HoursToExpire: 1})
	require.NoError(t, apiUsers.Create(users.AdminUser{Username: "alice"}))
	token, expiry, err := apiUsers.CreateToken("alice", "api", 1)
	require.NoError(t, err)
	require.NoError(t, apiUsers.UpdateToken("alice", token, expiry))
	r := httptest.NewRequest("GET", "/api/v1/events", nil)
	r.AddCookie(&http.Cookie{Name: cookieNameToken, Value: token})
	r = r.WithContext(context.WithValue(r.Context(), handlers.ContextKey(contextAPI), handlers.ContextValue{"user": "alice"}))
	require.True(t, eventSessionValid(r, config.AuthJWT, "event-test-secret-at-least-thirty-two-bytes"))
	wrongUser := r.WithContext(context.WithValue(r.Context(), handlers.ContextKey(contextAPI), handlers.ContextValue{"user": "bob"}))
	require.False(t, eventSessionValid(wrongUser, config.AuthJWT, "event-test-secret-at-least-thirty-two-bytes"))
	newToken, newExpiry, err := apiUsers.CreateToken("alice", "api", 1)
	require.NoError(t, err)
	require.NoError(t, apiUsers.UpdateToken("alice", newToken, newExpiry))
	require.False(t, eventSessionValid(r, config.AuthJWT, "event-test-secret-at-least-thirty-two-bytes"), "rotated cookie must stop an existing stream")
	expired, expiry, err := apiUsers.CreateToken("alice", "api", -1)
	require.NoError(t, err)
	require.NoError(t, apiUsers.UpdateToken("alice", expired, expiry))
	r.Header.Set("Cookie", cookieNameToken+"="+expired)
	require.False(t, eventSessionValid(r, config.AuthJWT, "event-test-secret-at-least-thirty-two-bytes"))
}

func TestEventPermissionSnapshotReusesAuthenticatedUser(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	previous := apiUsers
	t.Cleanup(func() { apiUsers = previous })
	secret := "event-test-secret-at-least-thirty-two-bytes"
	apiUsers = users.CreateUserManager(db).WithJWT(&config.YAMLConfigurationJWT{JWTSecret: secret, HoursToExpire: 1})
	require.NoError(t, apiUsers.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, apiUsers.CreatePermission(users.UserPermission{Username: "alice", Environment: "env", AccessType: int(users.AdminLevel), AccessValue: true}))
	token, expiry, err := apiUsers.CreateToken("alice", "api", 1)
	require.NoError(t, err)
	require.NoError(t, apiUsers.UpdateToken("alice", token, expiry))
	r := httptest.NewRequest("GET", "/api/v1/events", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r = r.WithContext(context.WithValue(r.Context(), handlers.ContextKey(contextAPI), handlers.ContextValue{"user": "alice"}))
	queries := 0
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("count_auth_reads", func(*gorm.DB) { queries++ }))
	pass := r.WithContext(users.WithPermissionCache(r.Context()))
	require.True(t, eventSessionValid(pass, config.AuthJWT, secret))
	require.True(t, apiUsers.CheckPermissionsContext(pass.Context(), "alice", users.QueryLevel, "env"))
	require.True(t, apiUsers.CheckPermissionsContext(pass.Context(), "alice", users.CarveLevel, "env"))
	require.Equal(t, 2, queries, "one token/user read plus one permissions read for both topics")
	require.NoError(t, db.Model(&users.UserPermission{}).Where("username = ?", "alice").Update("access_value", false).Error)
	pass = r.WithContext(users.WithPermissionCache(r.Context()))
	require.True(t, eventSessionValid(pass, config.AuthJWT, secret))
	require.False(t, apiUsers.CheckPermissionsContext(pass.Context(), "alice", users.QueryLevel, "env"))
	require.Equal(t, 4, queries, "the next batch must refresh both rows")
}
