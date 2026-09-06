package health

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSampleRuntimeMetricsReportsLiveNumbers is the guard against an upstream
// metric rename: every field below is mapped from a runtime/metrics name, and
// a renamed metric silently returns zero.
func TestSampleRuntimeMetricsReportsLiveNumbers(t *testing.T) {
	// Force a collection so the GC-derived fields cannot be zero by accident.
	runtime.GC()

	started := time.Now().Add(-90 * time.Second)
	s := SampleRuntimeMetrics(started)

	require.InDelta(t, 90, s.UptimeSeconds, 2)
	require.Greater(t, s.Goroutines, 0)
	require.Greater(t, s.HeapAlloc, uint64(0), "metric %q may have been renamed", mHeapObjectsBytes)
	require.Greater(t, s.Sys, uint64(0), "metric %q may have been renamed", mTotalBytes)
	require.Greater(t, s.TotalAlloc, uint64(0), "metric %q may have been renamed", mAllocsBytes)
	require.Greater(t, s.HeapObjects, uint64(0), "metric %q may have been renamed", mLiveObjects)
	require.Greater(t, s.NextGC, uint64(0), "metric %q may have been renamed", mHeapGoal)
	require.Greater(t, s.NumGC, uint32(0), "metric %q may have been renamed", mGCCycles)
	require.Greater(t, s.PauseTotalNs, uint64(0), "metric %q may have been renamed", mGCPauses)
	require.GreaterOrEqual(t, s.Mallocs, s.Frees, "mallocs cannot trail frees")
	require.GreaterOrEqual(t, s.HeapSys, s.HeapAlloc)
}

// TestSampleRuntimeMetricsAgreesWithReadMemStats pins the two samplers to the
// same order of magnitude. They read the same counters at slightly different
// instants, so this is a sanity band, not an equality check.
func TestSampleRuntimeMetricsAgreesWithReadMemStats(t *testing.T) {
	started := time.Now()
	stw := Snapshot(started)
	cheap := SampleRuntimeMetrics(started)

	require.InEpsilon(t, float64(stw.Sys), float64(cheap.Sys), 0.25,
		"total memory should agree closely between the two samplers")
	require.InEpsilon(t, float64(stw.HeapObjects), float64(cheap.HeapObjects), 0.75,
		"live object counts should be in the same ballpark")
	require.Equal(t, stw.NumGC, cheap.NumGC, "GC cycle counts are exact in both")
}

// TestSampleRuntimeMetricsLeavesUnavailableFieldsZero documents the two fields
// runtime/metrics cannot supply, so a future reader does not mistake them for
// a bug.
func TestSampleRuntimeMetricsLeavesUnavailableFieldsZero(t *testing.T) {
	s := SampleRuntimeMetrics(time.Now())
	require.Zero(t, s.LastGC, "no runtime/metrics equivalent for the last-GC timestamp")
	require.Zero(t, s.Lookups, "deprecated in MemStats too")
}
