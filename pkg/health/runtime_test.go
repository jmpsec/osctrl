package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSnapshotReportsLiveRuntimeNumbers(t *testing.T) {
	started := time.Now().Add(-90 * time.Second)
	s := Snapshot(started)

	require.InDelta(t, 90, s.UptimeSeconds, 2)
	require.Greater(t, s.Goroutines, 0)
	require.Greater(t, s.HeapAlloc, uint64(0))
	require.Greater(t, s.Sys, uint64(0))
	require.GreaterOrEqual(t, s.Mallocs, s.Frees, "mallocs cannot trail frees")
}
