package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// A query is stored and sent to every targeted node, so its text is capped
// where queries are run or saved.
func TestQueryTextLengthLimit(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "q")
	f.tier(t, "q", f.env.UUID, users.QueryLevel, users.TierStandard)
	tooLong := "select '" + strings.Repeat("a", queries.MaxQueryLength) + "';"

	rr := f.run(t, false, "q", types.ApiDistributedQueryRequest{Query: tooLong})
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "query too long")
	var n int64
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Count(&n).Error)
	require.Zero(t, n)

	save := func(handler http.HandlerFunc, body any, name string) *httptest.ResponseRecorder {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		r := consoleRequest(http.MethodPost, "/saved", b, "q")
		r.SetPathValue("env", f.env.Name)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	rr = save(f.h.SavedQueryCreateHandler, types.SavedQueryCreateRequest{Name: "big", Query: tooLong}, "")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "query too long")

	rr = save(f.h.SavedQueryCreateHandler, types.SavedQueryCreateRequest{Name: "ok", Query: "select 1;"}, "")
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	rr = save(f.h.SavedQueryUpdateHandler, types.SavedQueryUpdateRequest{Query: tooLong}, "ok")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "query too long")
}
