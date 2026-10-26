package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestEnvActionsKeepHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/environments/{env}/{target}/{action}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, types.ApiGenericResponse{Message: r.PathValue("target") + "/" + r.PathValue("action")})
	})
	mux.HandleFunc("GET /api/v1/environments/map/id", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"1": map[string]any{"name": "dev"}})
	})
	api := newRealURLServer(t, mux)
	for target, fns := range map[string]map[string]func(string) (string, error){
		"enroll": {"extend": api.ExtendEnrollment, "rotate": api.RotateEnrollment, "expire": api.ExpireEnrollment, "notexpire": api.NotexpireEnrollment},
		"remove": {"extend": api.ExtendRemove, "rotate": api.RotateRemove, "expire": api.ExpireRemove, "notexpire": api.NotexpireRemove},
	} {
		for action, fn := range fns {
			msg, err := fn("dev")
			require.NoError(t, err, "%s %s", target, action)
			require.Equal(t, target+"/"+action, msg)
		}
	}
	m, err := api.GetEnvMap()
	require.NoError(t, err)
	require.Len(t, m, 1)
}

func TestGetQueriesDecodesPagedResponse(t *testing.T) {
	mux := http.NewServeMux()
	var pages []string
	mux.HandleFunc("GET /api/v1/queries/{env}/list/{target}", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("page")
		pages = append(pages, p+"/"+r.URL.Query().Get("page_size"))
		item := queries.DistributedQuery{Name: "q" + p, Query: "select 1"}
		writeJSON(w, types.QueriesPagedResponse{Items: []queries.DistributedQuery{item}, Page: 1, PageSize: 500, TotalItems: 2, TotalPages: 2})
	})
	api := newRealURLServer(t, mux)
	qs, err := api.GetQueries("all", "dev")
	require.NoError(t, err)
	require.Len(t, qs, 2)
	require.Equal(t, []string{"1/500", "2/500"}, pages)
	require.Equal(t, "q2", qs[1].Name)
}

func TestGetCarvesDecodesPagedResponse(t *testing.T) {
	mux := http.NewServeMux()
	var got string
	mux.HandleFunc("GET /api/v1/carves/{env}/list", func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("page") + "/" + r.URL.Query().Get("page_size")
		writeJSON(w, types.CarvesPagedResponse{Items: []queries.DistributedQuery{{Name: "c1", Type: queries.CarveQueryType}}, Page: 1, PageSize: 500, TotalItems: 1, TotalPages: 1})
	})
	api := newRealURLServer(t, mux)
	cs, err := api.GetCarves("dev")
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.Equal(t, "c1", cs[0].Name)
	require.Equal(t, "1/500", got)
}

func TestGetAuditLogsDecodesPagedResponse(t *testing.T) {
	mux := http.NewServeMux()
	var got []string
	mux.HandleFunc("GET /api/v1/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query().Get("page")+"/"+r.URL.Query().Get("page_size"))
		writeJSON(w, types.AuditLogsPagedResponse{Items: []types.AuditLogView{{ID: 7, CreatedAt: time.Unix(1700000000, 0), Username: "admin", Line: "x", LogType: 1, EnvironmentID: 3}}, Page: 1, PageSize: 500, TotalItems: 1, TotalPages: 1})
	})
	api := newRealURLServer(t, mux)
	als, err := api.GetAuditLogs()
	require.NoError(t, err)
	require.Equal(t, []string{"1/500"}, got)
	require.Len(t, als, 1)
	require.Equal(t, uint(7), als[0].ID)
	require.Equal(t, "admin", als[0].Username)
	require.Equal(t, uint(3), als[0].EnvironmentID)
	require.False(t, als[0].CreatedAt.IsZero())
}

func TestAddTagSendsCustom(t *testing.T) {
	mux := http.NewServeMux()
	var body types.ApiTagsRequest
	mux.HandleFunc("POST /api/v1/tags/{env}/add", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, types.ApiGenericResponse{Message: "ok"})
	})
	api := newRealURLServer(t, mux)
	_, err := api.AddTag("dev", "t", "#fff", "icon", "d", 3, "custom-val")
	require.NoError(t, err)
	require.Equal(t, "custom-val", body.Custom)
}

func TestGetQueriesEmptyList(t *testing.T) {
	mux := http.NewServeMux()
	hits := 0
	mux.HandleFunc("GET /api/v1/queries/{env}/list/{target}", func(w http.ResponseWriter, r *http.Request) {
		hits++
		writeJSON(w, types.QueriesPagedResponse{Items: []queries.DistributedQuery{}, Page: 1, PageSize: 500})
	})
	qs, err := newRealURLServer(t, mux).GetQueries("all", "dev")
	require.NoError(t, err)
	require.Empty(t, qs)
	require.Equal(t, 1, hits)
}

func TestGetQueriesErrorMidPagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/queries/{env}/list/{target}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		writeJSON(w, types.QueriesPagedResponse{Items: []queries.DistributedQuery{{Name: "q1"}}, Page: 1, PageSize: 500, TotalItems: 2, TotalPages: 2})
	})
	_, err := newRealURLServer(t, mux).GetQueries("all", "dev")
	require.Error(t, err)
}
