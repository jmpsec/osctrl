package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestLockoutErrorResponse(t *testing.T) {
	cases := []struct {
		err    error
		status int
		text   string
	}{
		{users.ErrSelfDemote, http.StatusForbidden, "super-admins cannot self-demote via this endpoint"},
		{fmt.Errorf("%w: only 1 admin user(s) remain", users.ErrLastSuperAdmin), http.StatusConflict, "refusing to demote the last super-admin"},
		{errors.New("boom"), http.StatusInternalServerError, "error checking admin count"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		lockoutErrorResponse(w, c.err)
		require.Equal(t, c.status, w.Code)
		require.Contains(t, w.Body.String(), c.text)
	}
}
