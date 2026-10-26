package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&out, pr); close(done) }()
	stdout := os.Stdout
	os.Stdout = pw
	runErr := func() error {
		defer func() { os.Stdout = stdout; _ = pw.Close(); <-done; _ = pr.Close() }()
		return fn()
	}()
	require.NoError(t, runErr)
	return out.String()
}

func TestPrintCarveQueries(t *testing.T) {
	oFormat := formatFlag
	t.Cleanup(func() { formatFlag = oFormat })
	qs := []queries.DistributedQuery{{Name: "carve-1", Creator: "admin", Query: "select * from carves", Type: queries.CarveQueryType, Expiration: time.Unix(0, 0)}}
	formatFlag = prettyFormat
	out := captureStdout(t, func() error { return printCarveQueries("all", qs) })
	require.Contains(t, out, "Existing all carve queries (1)")
	require.Contains(t, out, "carve-1")
	formatFlag = csvFormat
	out = captureStdout(t, func() error { return printCarveQueries("all", qs) })
	require.Contains(t, out, "Name,Creator,Query")
	require.Contains(t, out, "carve-1,admin")
	formatFlag = prettyFormat
	out = captureStdout(t, func() error { return printCarveQueries("all", nil) })
	require.Contains(t, out, "No all carve queries")
}

func TestCarveQueryToRow(t *testing.T) {
	r := carveQueryToRow(queries.DistributedQuery{Name: "c1", CarveStatus: "completed"})
	require.Equal(t, "c1", r.QueryName)
	require.Equal(t, "completed", r.Status)
	require.Empty(t, r.Path)
	// Without a derived carve status, it falls back to the query status.
	q := queries.DistributedQuery{Name: "c2", Active: true}
	require.Equal(t, queryStatus(q), carveQueryToRow(q).Status)
}

func TestAPIStoreCarvesMapsCarveQueries(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/carves/{env}/list", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.CarvesPagedResponse{
			Items: []queries.DistributedQuery{{Name: "c1", CarveStatus: "completed"}}, Page: 1, PageSize: 500, TotalItems: 1, TotalPages: 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	api, err := apiclient.CreateAPI(apiclient.JSONConfigurationAPI{URL: srv.URL, Token: "t"}, false)
	require.NoError(t, err)
	rows, err := newAPIStore(api).Carves("dev")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "c1", rows[0].QueryName)
	require.Equal(t, "completed", rows[0].Status)
}
