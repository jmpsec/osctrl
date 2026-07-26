package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
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
}
