package carves

import (
	"encoding/base64"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func blockReq(id int, data string) types.CarveBlockRequest {
	return types.CarveBlockRequest{SessionID: "sess", RequestID: "req", BlockID: id, Data: base64.StdEncoding.EncodeToString([]byte(data))}
}

// Blocks are only stored for an initialized, in-progress carve, within its
// declared bounds and once each; completion needs every distinct block and is
// claimed exactly once.
func TestStoreBlockAndClaimCompletion(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	c := CreateFileCarves(db, config.CarverDB, nil)
	require.NoError(t, c.CreateCarve(CarvedFile{CarveID: "scheduled", RequestID: "req", Status: StatusScheduled}))
	require.NoError(t, c.CreateCarve(CarvedFile{CarveID: "c", RequestID: "req", SessionID: "sess", Status: StatusInProgress, TotalBlocks: 2, BlockSize: 4}))

	// [17] An empty session never selects the scheduled row.
	_, err = c.GetBySession("")
	require.Error(t, err)

	carve, err := c.GetBySession("sess")
	require.NoError(t, err)
	for _, bad := range []types.CarveBlockRequest{blockReq(-1, "a"), blockReq(2, "a"), blockReq(0, "too long"), {SessionID: "sess", BlockID: 0, Data: "%%%"}} {
		require.ErrorIs(t, c.StoreBlock(carve, "env", "NODE", bad), ErrBlockRejected)
	}

	// [21] A duplicate block 0 cannot stand in for the missing block 1.
	require.NoError(t, c.StoreBlock(carve, "env", "NODE", blockReq(0, "abcd")))
	require.NoError(t, c.StoreBlock(carve, "env", "NODE", blockReq(0, "abcd")))
	require.NoError(t, c.CompleteBlock("sess"))
	claimed, err := c.ClaimCompletion("sess")
	require.NoError(t, err)
	require.False(t, claimed)
	var n int64
	require.NoError(t, db.Model(&CarvedBlock{}).Where("session_id = ?", "sess").Count(&n).Error)
	require.EqualValues(t, 1, n, "a duplicate is acknowledged, not stored")

	// [10] Completion is claimed once, by whichever worker sees all blocks.
	require.NoError(t, c.StoreBlock(carve, "env", "NODE", blockReq(1, "ef")))
	claimed, err = c.ClaimCompletion("sess")
	require.NoError(t, err)
	require.True(t, claimed)
	claimed, err = c.ClaimCompletion("sess")
	require.NoError(t, err)
	require.False(t, claimed)

	// [21] Nothing is accepted after completion.
	carve, err = c.GetBySession("sess")
	require.NoError(t, err)
	require.Equal(t, 2, carve.CompletedBlocks)
	require.ErrorIs(t, c.StoreBlock(carve, "env", "NODE", blockReq(1, "zz")), ErrBlockRejected)

	// Rows stored as duplicates before this change are written once.
	require.NoError(t, db.Create(&CarvedBlock{SessionID: "sess", BlockID: 0, Data: "dup"}).Error)
	blocks, err := c.GetBlocks("sess")
	require.NoError(t, err)
	require.Len(t, blocks, 2)
}
