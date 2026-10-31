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
