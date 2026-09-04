package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestProjectNodeAddsUptimeWhenPostureEnabled(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:node_uptime_projection?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	pm := posture.NewPostureManager(db)
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"uptime", []byte(`[{"days":"2","hours":"4","minutes":"6","seconds":"8","total_seconds":"187568"}]`)); err != nil {
		t.Fatalf("ingest uptime: %v", err)
	}
	h := &HandlersApi{
		Posture:        pm,
		PostureEnabled: true,
	}

	view := h.projectNode(nodes.OsqueryNode{UUID: "node-a"})

	if view.Uptime == nil {
		t.Fatal("expected uptime")
	}
	if view.Uptime.Days != 2 || view.Uptime.Hours != 4 || view.Uptime.Minutes != 6 || view.Uptime.Seconds != 8 {
		t.Fatalf("unexpected uptime: %+v", view.Uptime)
	}
}

func TestProjectNodeAddsPostureRiskWhenPostureEnabled(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:node_posture_risk_projection?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	pm := posture.NewPostureManager(db)
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"disk_encryption", []byte(`[{"name":"/dev/sda","encrypted":"0","type":"ext4"}]`)); err != nil {
		t.Fatalf("ingest posture: %v", err)
	}
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"listening_ports", []byte(`[{"port":"23","address":"0.0.0.0"}]`)); err != nil {
		t.Fatalf("ingest listening ports: %v", err)
	}
	h := &HandlersApi{
		Posture:        pm,
		PostureEnabled: true,
	}

	view := h.projectNode(nodes.OsqueryNode{UUID: "node-a"})

	if view.Posture == nil {
		t.Fatal("expected posture summary")
	}
	// An unencrypted disk is a failing critical control, which escalates
	// the risk level to critical regardless of the numeric score.
	if view.Posture.RiskLevel != "critical" {
		t.Fatalf("unexpected risk level %q", view.Posture.RiskLevel)
	}
}

func TestProjectNodeOmitsUptimeWhenPostureDisabled(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:node_uptime_disabled?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	pm := posture.NewPostureManager(db)
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"uptime", []byte(`[{"days":"2","hours":"4","minutes":"6","seconds":"8"}]`)); err != nil {
		t.Fatalf("ingest uptime: %v", err)
	}
	h := &HandlersApi{
		Posture:        pm,
		PostureEnabled: false,
	}

	view := h.projectNode(nodes.OsqueryNode{UUID: "node-a"})

	if view.Uptime != nil {
		t.Fatalf("expected uptime to be hidden while posture is disabled: %+v", view.Uptime)
	}
	if view.Posture != nil {
		t.Fatalf("expected posture summary to be hidden while posture is disabled: %+v", view.Posture)
	}
}

func TestProjectNodeAddsTagsAndHealth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:node_tags_health_projection?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tagMgr := tags.CreateTagManager(db)
	node := nodes.OsqueryNode{
		ID:            42,
		UUID:          "node-a",
		EnvironmentID: 7,
		LastSeen:      time.Now().Add(-1 * time.Hour),
	}
	if err := tagMgr.TagNode("prod", node, "alice", false, tags.TagTypeTag, ""); err != nil {
		t.Fatalf("tag node: %v", err)
	}
	h := &HandlersApi{Tags: tagMgr}

	view := h.projectNode(node)

	if len(view.Tags) != 1 {
		t.Fatalf("expected one projected tag, got %+v", view.Tags)
	}
	if view.Tags[0].Name != "prod" {
		t.Fatalf("unexpected tag %+v", view.Tags[0])
	}
	if view.Health.Status != "healthy" {
		t.Fatalf("expected healthy node, got %+v", view.Health)
	}
}

func TestProjectNodeHealthPrioritizesOffline(t *testing.T) {
	h := &HandlersApi{}

	view := h.projectNode(nodes.OsqueryNode{
		UUID:     "node-offline",
		LastSeen: time.Now().Add(-100 * time.Hour),
	})

	if view.Health.Status != "offline" {
		t.Fatalf("expected offline health, got %+v", view.Health)
	}
}

func TestProjectNodeHealthUsesPostureRisk(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:node_health_posture_projection?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	pm := posture.NewPostureManager(db)
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"disk_encryption", []byte(`[{"name":"/dev/sda","encrypted":"0","type":"ext4"}]`)); err != nil {
		t.Fatalf("ingest posture: %v", err)
	}
	if err := pm.IngestResult("node-a", "env", posture.QueryPrefix+"listening_ports", []byte(`[{"port":"23","address":"0.0.0.0"}]`)); err != nil {
		t.Fatalf("ingest posture: %v", err)
	}
	h := &HandlersApi{
		Posture:        pm,
		PostureEnabled: true,
	}

	view := h.projectNode(nodes.OsqueryNode{
		UUID:     "node-a",
		LastSeen: time.Now().Add(-1 * time.Hour),
	})

	if view.Health.Status != "at_risk" {
		t.Fatalf("expected at_risk health, got %+v", view.Health)
	}
}

func TestNodePostureHandlersRequireAdminLevel(t *testing.T) {
	_, h, env, node := setupConsoleHandlers(t)
	if err := h.Users.CreatePermission(users.UserPermission{
		Username:      "bob",
		AccessType:    int(users.UserLevel),
		AccessValue:   true,
		Environment:   env.UUID,
		EnvironmentID: env.ID,
	}); err != nil {
		t.Fatalf("create user-level permission: %v", err)
	}

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{
			name:    "posture",
			handler: h.NodePostureHandler,
			path:    "/api/v1/nodes/env/node/NODE-UUID/posture",
		},
		{
			name:    "posture score",
			handler: h.NodePostureScoreHandler,
			path:    "/api/v1/nodes/env/node/NODE-UUID/posture/score",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.SetPathValue("env", env.Name)
			req.SetPathValue("uuid", node.UUID)
			req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "bob"}))
			rr := httptest.NewRecorder()

			tc.handler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
			}
		})
	}
}
