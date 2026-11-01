package carves

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// InitCarve must only start the requesting node's own scheduled carve.
func TestInitCarveScopedToNode(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	c := CreateFileCarves(db, "db", nil)
	// Two nodes in different environments targeted by the same carve request.
	require.NoError(t, c.CreateCarve(CarvedFile{CarveID: "carve-a", RequestID: "req", NodeID: 1, EnvironmentID: 1, Status: StatusScheduled}))
	require.NoError(t, c.CreateCarve(CarvedFile{CarveID: "carve-b", RequestID: "req", NodeID: 2, EnvironmentID: 2, Status: StatusScheduled}))

	// Node 2 naming node 1's carve is rejected and leaves it untouched.
	require.Error(t, c.InitCarve(types.CarveInitRequest{CarveID: "carve-a", RequestID: "req", BlockCount: 9}, "evil", 2, 2))
	a, err := c.GetByCarve("carve-a")
	require.NoError(t, err)
	require.Equal(t, StatusScheduled, a.Status)
	require.Empty(t, a.SessionID)

	// Node 2 initializing its own carve only touches that row.
	require.NoError(t, c.InitCarve(types.CarveInitRequest{CarveID: "carve-b", RequestID: "req", BlockCount: 3}, "sess-b", 2, 2))
	b, err := c.GetByCarve("carve-b")
	require.NoError(t, err)
	require.Equal(t, "sess-b", b.SessionID)
	require.Equal(t, StatusInProgress, b.Status)
	a, err = c.GetByCarve("carve-a")
	require.NoError(t, err)
	require.Empty(t, a.SessionID)

	// A second init of an in-progress carve is a conflicting transition.
	require.Error(t, c.InitCarve(types.CarveInitRequest{CarveID: "carve-b", RequestID: "req"}, "sess-2", 2, 2))
}
