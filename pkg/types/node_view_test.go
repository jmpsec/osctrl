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
