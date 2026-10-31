package queries

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestReplicaUsesReadDBWithoutSideEffects(t *testing.T) {
	primary, replica := &gorm.DB{}, &gorm.DB{}
	q := &Queries{DB: primary, ReadDB: replica, Cache: &QueryDispatchCache{}}
	r := q.Replica()
	assert.Same(t, replica, r.DB)
	assert.Nil(t, r.Cache)
	assert.Nil(t, r.Events)
	plain := &Queries{DB: primary}
	assert.Same(t, plain, plain.Replica())
}
