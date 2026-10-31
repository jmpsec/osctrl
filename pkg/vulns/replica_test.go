package vulns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// Only the copy reads the replica: Reader.DB stays the primary because
// RequestSync writes through it.
func TestReaderReplica(t *testing.T) {
	primary, replica := &gorm.DB{}, &gorm.DB{}
	rd := NewReader(primary, time.Hour)
	rd.ReadDB = replica
	r := rd.Replica()
	assert.Same(t, replica, r.DB)
	assert.Same(t, primary, rd.DB)
	assert.Equal(t, rd.StaleAfter, r.StaleAfter)
	assert.NotNil(t, r.now)
	plain := NewReader(primary, time.Hour)
	assert.Same(t, plain, plain.Replica())
}
