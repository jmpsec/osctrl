package auditlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// The replica copy is read-only: it must never record audit entries, which
// would be lost or rejected on a replica.
func TestReplicaNeverRecords(t *testing.T) {
	primary, replica := &gorm.DB{}, &gorm.DB{}
	m := &AuditLogManager{DB: primary, ReadDB: replica, Service: "api", Enabled: true}
	r := m.Replica()
	assert.Same(t, replica, r.DB)
	assert.False(t, r.Enabled)
	plain := &AuditLogManager{DB: primary}
	assert.Same(t, plain, plain.Replica())
}
