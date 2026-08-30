package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"testing"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// newTestAPI spins an httptest server answering the console / file-explorer /
// posture / saved-queries routes, returning the wired client.
func newTestAPI(t *testing.T) *OsctrlAPI {
	t.Helper()
	mux := http.NewServeMux()

	// Console routes
	mux.HandleFunc("POST /api/v1/console/{env}/nodes/{uuid}/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("env") != "dev" || r.PathValue("uuid") != "UUID1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer testtoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(ConsoleSessionResponse{
			Session:  console.Session{ID: 7, NodeUUID: "UUID1", CWD: "/", Platform: "linux"},
			NodeInfo: consoleNodeInfo{OsqueryVersion: "5.23.1"},
		})
	})
	mux.HandleFunc("DELETE /api/v1/console/{env}/sessions/{session_id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("session_id") != "7" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(types.ApiGenericResponse{Message: "console session closed"})
	})
	mux.HandleFunc("GET /api/v1/console/{env}/sessions/{session_id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(console.Session{ID: 7, CWD: "/etc"})
	})
	mux.HandleFunc("POST /api/v1/console/{env}/sessions/{session_id}/commands", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input       string `json:"input"`
			OsqueryMode bool   `json:"osquery_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(ConsoleCommandResponse{
			Command: console.Command{ID: 42, Input: body.Input, Status: console.StatusCompleted},
			Parsed:  console.ParsedCommand{Kind: console.CommandRemote, Command: "sql"},
		})
	})
	mux.HandleFunc("GET /api/v1/console/{env}/sessions/{session_id}/commands/{command_id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(console.Command{ID: 42, Status: console.StatusCompleted})
	})
	mux.HandleFunc("GET /api/v1/console/{env}/sessions/{session_id}/commands/{command_id}/results", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"hostname": "box1"}})
	})

	// File explorer routes
	mux.HandleFunc("POST /api/v1/file-explorer/{env}/nodes/{uuid}/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(fileExplorerSessionResponse{
			Session: fileexplorer.Session{ID: 9, Root: "/"},
		})
	})
	mux.HandleFunc("DELETE /api/v1/file-explorer/{env}/sessions/{session_id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("session_id") != "9" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(types.ApiGenericResponse{Message: "file explorer session closed"})
	})
	mux.HandleFunc("POST /api/v1/file-explorer/{env}/sessions/{session_id}/list", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(fileexplorer.Request{ID: 11, Action: "list", Path: body.Path, Status: fileexplorer.StatusCompleted})
	})
	mux.HandleFunc("POST /api/v1/file-explorer/{env}/sessions/{session_id}/stat", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(fileexplorer.Request{ID: 12, Action: "stat", Status: fileexplorer.StatusCompleted})
	})
	mux.HandleFunc("GET /api/v1/file-explorer/{env}/sessions/{session_id}/requests/{request_id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(fileexplorer.Request{ID: 11, Status: fileexplorer.StatusCompleted})
	})
	mux.HandleFunc("GET /api/v1/file-explorer/{env}/sessions/{session_id}/requests/{request_id}/results", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]fileexplorer.Entry{{Filename: "passwd", Directory: "/etc", Type: "regular"}})
	})

	// Posture routes
	mux.HandleFunc("GET /api/v1/nodes/{env}/node/{uuid}/posture", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]posture.NodePosture{{Category: "osquery_info", Summary: `[{"version":"5.23.1"}]`}})
	})
	mux.HandleFunc("GET /api/v1/nodes/{env}/node/{uuid}/posture/score", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(posture.PostureScore{
			TotalScore: 12,
			RiskLevel:  "medium",
			PassCount:  3,
			WarnCount:  1,
			FailCount:  0,
		})
	})
	mux.HandleFunc("GET /api/v1/posture/profiles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]posture.PostureProfile{{ID: "linux-server", Name: "Linux Server"}})
	})

	// Saved queries routes
	mux.HandleFunc("GET /api/v1/saved-queries/{env}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.SavedQueriesPagedResponse{
			Items: []types.SavedQueryView{{Name: "uptime", Query: "select * from uptime"}},
		})
	})
	mux.HandleFunc("POST /api/v1/saved-queries/{env}", func(w http.ResponseWriter, r *http.Request) {
		var body types.SavedQueryCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Query == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("PATCH /api/v1/saved-queries/{env}/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") != "uptime" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body types.SavedQueryUpdateRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(types.SavedQueryView{Name: "uptime", Query: body.Query})
	})
	mux.HandleFunc("DELETE /api/v1/saved-queries/{env}/{name}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.ApiGenericResponse{Message: "deleted"})
	})

	// Query samples + node logs
	mux.HandleFunc("GET /api/v1/queries/samples", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queries.QuerySamples)
	})
	mux.HandleFunc("GET /api/v1/logs/{type}/{env}/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"type":%q,"env":%q,"uuid":%q}`, r.PathValue("type"), r.PathValue("env"), r.PathValue("uuid"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return CreateAPI(JSONConfigurationAPI{URL: srv.URL, Token: "testtoken"}, false)
}

func TestConsoleClientRoundTrip(t *testing.T) {
	api := newTestAPI(t)

	res, err := api.CreateConsoleSession("dev", "UUID1")
	if err != nil {
		t.Fatalf("CreateConsoleSession: %v", err)
	}
	if res.Session.ID != 7 || res.Session.CWD != "/" || res.NodeInfo.OsqueryVersion != "5.23.1" {
		t.Fatalf("unexpected session response: %+v", res)
	}

	resp, err := api.SubmitConsoleCommand("dev", 7, "select * from uptime", false)
	if err != nil {
		t.Fatalf("SubmitConsoleCommand: %v", err)
	}
	if resp.Command.ID != 42 || resp.Parsed.Kind != console.CommandRemote {
		t.Fatalf("unexpected command response: %+v", resp)
	}

	cmd, err := api.GetConsoleCommand("dev", 7, 42)
	if err != nil {
		t.Fatalf("GetConsoleCommand: %v", err)
	}
	if cmd.Status != console.StatusCompleted {
		t.Fatalf("expected completed, got %s", cmd.Status)
	}

	rows, err := api.GetConsoleCommandResults("dev", 7, 42)
	if err != nil {
		t.Fatalf("GetConsoleCommandResults: %v", err)
	}
	if len(rows) != 1 || rows[0]["hostname"] != "box1" {
		t.Fatalf("unexpected rows: %+v", rows)
	}

	sess, err := api.GetConsoleSession("dev", 7)
	if err != nil {
		t.Fatalf("GetConsoleSession: %v", err)
	}
	if sess.CWD != "/etc" {
		t.Fatalf("expected cwd /etc, got %s", sess.CWD)
	}

	if err := api.CloseConsoleSession("dev", 7); err != nil {
		t.Fatalf("CloseConsoleSession: %v", err)
	}
}

func TestFileExplorerClientRoundTrip(t *testing.T) {
	api := newTestAPI(t)

	res, err := api.CreateFileExplorerSession("dev", "UUID1")
	if err != nil {
		t.Fatalf("CreateFileExplorerSession: %v", err)
	}
	if res.Session.ID != 9 {
		t.Fatalf("unexpected session id: %d", res.Session.ID)
	}

	req, err := api.SubmitFileExplorerList("dev", 9, "/etc")
	if err != nil {
		t.Fatalf("SubmitFileExplorerList: %v", err)
	}
	if req.ID != 11 || req.Path != "/etc" {
		t.Fatalf("unexpected request: %+v", req)
	}

	got, err := api.GetFileExplorerRequest("dev", 9, 11)
	if err != nil {
		t.Fatalf("GetFileExplorerRequest: %v", err)
	}
	if got.Status != fileexplorer.StatusCompleted {
		t.Fatalf("expected completed, got %s", got.Status)
	}

	entries, err := api.GetFileExplorerResults("dev", 9, 11)
	if err != nil {
		t.Fatalf("GetFileExplorerResults: %v", err)
	}
	if len(entries) != 1 || entries[0].Filename != "passwd" {
		t.Fatalf("unexpected entries: %+v", entries)
	}

	if _, err := api.SubmitFileExplorerStat("dev", 9, "/etc/passwd"); err != nil {
		t.Fatalf("SubmitFileExplorerStat: %v", err)
	}

	if err := api.CloseFileExplorerSession("dev", 9); err != nil {
		t.Fatalf("CloseFileExplorerSession: %v", err)
	}
}

func TestPostureClientRoundTrip(t *testing.T) {
	api := newTestAPI(t)

	records, err := api.GetNodePosture("dev", "UUID1")
	if err != nil {
		t.Fatalf("GetNodePosture: %v", err)
	}
	if len(records) != 1 || records[0].Category != "osquery_info" {
		t.Fatalf("unexpected records: %+v", records)
	}

	score, err := api.GetNodePostureScore("dev", "UUID1")
	if err != nil {
		t.Fatalf("GetNodePostureScore: %v", err)
	}
	if score.RiskLevel != "medium" || score.TotalScore != 12 {
		t.Fatalf("unexpected score: %+v", score)
	}

	profiles, err := api.GetPostureProfiles()
	if err != nil {
		t.Fatalf("GetPostureProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].ID != "linux-server" {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}
}

func TestSavedQueriesClientRoundTrip(t *testing.T) {
	api := newTestAPI(t)

	items, err := api.GetSavedQueries("dev")
	if err != nil {
		t.Fatalf("GetSavedQueries: %v", err)
	}
	if len(items) != 1 || items[0].Name != "uptime" {
		t.Fatalf("unexpected items: %+v", items)
	}

	if err := api.CreateSavedQuery("dev", "uptime", "select * from uptime"); err != nil {
		t.Fatalf("CreateSavedQuery: %v", err)
	}

	if err := api.UpdateSavedQuery("dev", "uptime", "select * from system_info"); err != nil {
		t.Fatalf("UpdateSavedQuery: %v", err)
	}

	if err := api.DeleteSavedQuery("dev", "uptime"); err != nil {
		t.Fatalf("DeleteSavedQuery: %v", err)
	}
}

func TestQuerySamplesAndNodeLogs(t *testing.T) {
	api := newTestAPI(t)

	samples, err := api.GetQuerySamples()
	if err != nil {
		t.Fatalf("GetQuerySamples: %v", err)
	}
	if len(samples) == 0 {
		t.Fatalf("expected non-empty sample library")
	}

	body, err := api.GetNodeLogs("dev", "result", "UUID1")
	if err != nil {
		t.Fatalf("GetNodeLogs: %v", err)
	}
	var parsed struct {
		Type string `json:"type"`
		Env  string `json:"env"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("logs body not JSON: %v", err)
	}
	if parsed.Type != "result" || parsed.Env != "dev" {
		t.Fatalf("unexpected logs body: %s", body)
	}
}

func TestStoreCastErrors(t *testing.T) {
	// dbStore does not implement the console/posture/saved surfaces.
	store := newDBStore()
	if _, err := storeConsole(store); err == nil {
		t.Fatal("expected storeConsole to reject dbStore")
	}
	if _, err := storePosture(store); err == nil {
		t.Fatal("expected storePosture to reject dbStore")
	}
	if _, err := storeSaved(store); err == nil {
		t.Fatal("expected storeSaved to reject dbStore")
	}
}

func TestAPIStoreImplementsExtraSurfaces(t *testing.T) {
	api := newTestAPI(t)
	store := newAPIStore(api)
	if _, err := storeConsole(store); err != nil {
		t.Fatalf("apiStore should implement consoleStore: %v", err)
	}
	if _, err := storePosture(store); err != nil {
		t.Fatalf("apiStore should implement postureStore: %v", err)
	}
	if _, err := storeSaved(store); err != nil {
		t.Fatalf("apiStore should implement savedStore: %v", err)
	}
}

func TestColumnKeysAndIndent(t *testing.T) {
	keys := columnKeys(map[string]any{"b": 1, "a": 2, "c": 3})
	if len(keys) != 3 || keys[0] != "a" || keys[2] != "c" {
		t.Fatalf("columnKeys not sorted: %v", keys)
	}
	if got := indentLines("x\ny", "  "); got != "  x\n  y" {
		t.Fatalf("indentLines: %q", got)
	}
}

func TestConsoleURLPaths(t *testing.T) {
	// Sanity-check the URL shape the client builds matches the server route
	// table (path.Join collapses leading slashes but preserves ordering).
	want := "/api/v1/console/dev/sessions/7/commands/42/results"
	got := path.Join(APIPath, "/console", "dev", "sessions", strconv.FormatUint(uint64(7), 10),
		"commands", strconv.FormatUint(uint64(42), 10), "results")
	if got != want {
		t.Fatalf("path mismatch: got %s want %s", got, want)
	}
}
