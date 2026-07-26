package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
)

func TestProjectNodeOmitsNodeKeyByDefault(t *testing.T) {
	view := ProjectNode(nodes.OsqueryNode{
		ID:        1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		NodeKey:   "secret-node-key",
		UUID:      "11111111-2222-3333-4444-555555555555",
		Hostname:  "web-01",
	})

	body, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "secret-node-key") {
		t.Fatalf("projected node leaked node_key: %s", string(body))
	}
}

func TestNodeViewMarshalsNodeKeyWhenExplicitlyAttached(t *testing.T) {
	view := ProjectNode(nodes.OsqueryNode{
		ID:        1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UUID:      "11111111-2222-3333-4444-555555555555",
		Hostname:  "web-01",
	})
	view.NodeKey = "secret-node-key"

	body, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"node_key":"secret-node-key"`) {
		t.Fatalf("projected node missing explicit node_key: %s", string(body))
	}
}

func TestProjectNodeWithUptimeAddsOptionalUptime(t *testing.T) {
	view := ProjectNodeWithUptime(nodes.OsqueryNode{
		ID:        1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UUID:      "11111111-2222-3333-4444-555555555555",
		Hostname:  "web-01",
	}, &NodeUptime{
		Days:         7,
		Hours:        3,
		Minutes:      12,
		Seconds:      9,
		TotalSeconds: 616329,
		LastSeen:     time.Date(2026, 7, 26, 10, 30, 0, 0, time.UTC),
	})

	body, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"uptime"`,
		`"days":7`,
		`"hours":3`,
		`"minutes":12`,
		`"seconds":9`,
		`"total_seconds":616329`,
		`"last_seen":"2026-07-26T10:30:00Z"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("projected node missing %s: %s", want, string(body))
		}
	}
}
