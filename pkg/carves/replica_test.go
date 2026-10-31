package carves

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestReplicaUsesReadDBWithoutSideEffects(t *testing.T) {
	primary, replica := &gorm.DB{}, &gorm.DB{}
	c := &Carves{DB: primary, ReadDB: replica, S3: &CarverS3{}, Carver: "s3"}
	r := c.Replica()
	assert.Same(t, replica, r.DB)
	assert.Nil(t, r.S3)
	assert.Nil(t, r.Events)
	plain := &Carves{DB: primary}
	assert.Same(t, plain, plain.Replica())
}
