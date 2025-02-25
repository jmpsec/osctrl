package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSameAccessTrue(t *testing.T) {
	acc1 := EnvAccess{
		User: true,
		Query: true,
		Carve: false,
		Admin: false,
	}
	acc2 := EnvAccess{
		User: true,
		Query: true,
		Carve: false,
		Admin: false,
	}
	assert.Equal(t, true, SameAccess(acc1, acc2))
}

func TestSameAccessFalse(t *testing.T) {
	acc1 := EnvAccess{
		User: true,
		Query: true,
		Carve: false,
		Admin: false,
	}
	acc2 := EnvAccess{
		User: true,
		Query: false,
		Carve: false,
		Admin: false,
	}
	assert.Equal(t, false, SameAccess(acc1, acc2))
}

func TestGenEnvAccessAdmin(t *testing.T) {
	acc := EnvAccess{
		User: true,
		Query: true,
		Carve: true,
		Admin: true,
	}
	assert.Equal(t, acc, GenEnvAccess(true, false, false, false))
}

func TestGenEnvAccessQueryUser(t *testing.T) {
	acc := EnvAccess{
		User: true,
		Query: true,
		Carve: false,
		Admin: false,
	}
	assert.Equal(t, acc, GenEnvAccess(false, false, true, true))
}
