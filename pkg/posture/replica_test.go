package posture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

type replicaEvidence struct{ EvidenceSource }

// The replica copy keeps the evidence source: without it, risk levels on the
// node list would drop the vulnerability evidence and change.
func TestReplicaKeepsEvidence(t *testing.T) {
	primary, replica := &gorm.DB{}, &gorm.DB{}
	ev := replicaEvidence{}
	pm := &PostureManager{DB: primary, ReadDB: replica, Evidence: ev}
	r := pm.Replica()
	assert.Same(t, replica, r.DB)
	assert.Equal(t, ev, r.Evidence)
	plain := &PostureManager{DB: primary}
	assert.Same(t, plain, plain.Replica())
}

// When a replica-backed evidence source is set, the replica copy uses it, so
// node-list risk levels read both posture rows and findings from the replica.
func TestReplicaPrefersReadEvidence(t *testing.T) {
	type tagged struct {
		EvidenceSource
		name string
	}
	pm := &PostureManager{DB: &gorm.DB{}, ReadDB: &gorm.DB{},
		Evidence: tagged{name: "primary"}, ReadEvidence: tagged{name: "replica"}}
	assert.Equal(t, tagged{name: "replica"}, pm.Replica().Evidence)
	assert.Equal(t, tagged{name: "primary"}, pm.Evidence)
	plain := &PostureManager{DB: &gorm.DB{}, ReadEvidence: tagged{name: "replica"}}
	assert.Same(t, plain, plain.Replica())
}
