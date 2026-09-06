package health

import (
	"math"
	"runtime"
	"runtime/metrics"
	"time"
)

// metrics.go — the same numbers Snapshot reports, sampled without stopping
// the world.
//
// Snapshot (runtime.go) calls runtime.ReadMemStats, which STOPS THE WORLD.
// That is acceptable on the API request path, where it runs when an operator
// opens a page. It is not acceptable inside osctrl-tls, which samples on a
// 60s heartbeat while serving the log ingest path — so osctrl-tls uses this
// instead. runtime/metrics reads the same underlying counters without a
// global pause.
//
// Two fields have no runtime/metrics equivalent and stay zero here:
//
//   - LastGC (wall-clock time of the last collection) — the package exposes
//     cycle counts, not timestamps.
//   - Lookups — deprecated in MemStats and always zero there too.
//
// PauseTotalNs is derived from the /gc/pauses:seconds histogram, so it is an
// approximation (bucket midpoints), not the exact figure ReadMemStats gives.

// Metric names sampled for one runtime snapshot. Kept in one block so an
// upstream rename shows up as a zero value in exactly one place.
const (
	mHeapObjectsBytes = "/memory/classes/heap/objects:bytes"
	mHeapUnusedBytes  = "/memory/classes/heap/unused:bytes"
	mHeapFreeBytes    = "/memory/classes/heap/free:bytes"
	mHeapReleased     = "/memory/classes/heap/released:bytes"
	mHeapStacks       = "/memory/classes/heap/stacks:bytes"
	mOSStacks         = "/memory/classes/os-stacks:bytes"
	mMSpanInuse       = "/memory/classes/metadata/mspan/inuse:bytes"
	mMSpanFree        = "/memory/classes/metadata/mspan/free:bytes"
	mMCacheInuse      = "/memory/classes/metadata/mcache/inuse:bytes"
	mMCacheFree       = "/memory/classes/metadata/mcache/free:bytes"
	mMetadataOther    = "/memory/classes/metadata/other:bytes"
	mProfilingBuckets = "/memory/classes/profiling/buckets:bytes"
	mOtherBytes       = "/memory/classes/other:bytes"
	mTotalBytes       = "/memory/classes/total:bytes"
	mAllocsBytes      = "/gc/heap/allocs:bytes"
	mAllocsObjects    = "/gc/heap/allocs:objects"
	mFreesObjects     = "/gc/heap/frees:objects"
	mLiveObjects      = "/gc/heap/objects:objects"
	mHeapGoal         = "/gc/heap/goal:bytes"
	mGCCycles         = "/gc/cycles/total:gc-cycles"
	mGCPauses         = "/gc/pauses:seconds"
)

// SampleRuntimeMetrics reports the runtime state without stopping the world.
// Use it anywhere sampling happens on a timer; use Snapshot on a request path
// where the exact MemStats numbers are worth a brief pause.
func SampleRuntimeMetrics(startedAt time.Time) RuntimeStats {
	samples := []metrics.Sample{
		{Name: mHeapObjectsBytes}, {Name: mHeapUnusedBytes}, {Name: mHeapFreeBytes},
		{Name: mHeapReleased}, {Name: mHeapStacks}, {Name: mOSStacks},
		{Name: mMSpanInuse}, {Name: mMSpanFree}, {Name: mMCacheInuse}, {Name: mMCacheFree},
		{Name: mMetadataOther}, {Name: mProfilingBuckets}, {Name: mOtherBytes},
		{Name: mTotalBytes}, {Name: mAllocsBytes}, {Name: mAllocsObjects},
		{Name: mFreesObjects}, {Name: mLiveObjects}, {Name: mHeapGoal},
		{Name: mGCCycles}, {Name: mGCPauses},
	}
	metrics.Read(samples)

	v := make(map[string]uint64, len(samples))
	var pauseTotalNs uint64
	for _, s := range samples {
		switch s.Value.Kind() {
		case metrics.KindUint64:
			v[s.Name] = s.Value.Uint64()
		case metrics.KindFloat64Histogram:
			if s.Name == mGCPauses {
				pauseTotalNs = histogramTotalNs(s.Value.Float64Histogram())
			}
		default:
			// KindBad means this Go build does not know the metric. Leave it
			// at zero rather than guessing — a zeroed field is honest, a
			// fabricated one is not.
		}
	}

	heapAlloc := v[mHeapObjectsBytes]
	heapInuse := heapAlloc + v[mHeapUnusedBytes]
	heapIdle := v[mHeapFreeBytes] + v[mHeapReleased]

	return RuntimeStats{
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		Alloc:         heapAlloc,
		TotalAlloc:    v[mAllocsBytes],
		Sys:           v[mTotalBytes],
		Mallocs:       v[mAllocsObjects],
		Frees:         v[mFreesObjects],
		HeapAlloc:     heapAlloc,
		HeapSys:       heapInuse + heapIdle,
		HeapIdle:      heapIdle,
		HeapInuse:     heapInuse,
		HeapReleased:  v[mHeapReleased],
		HeapObjects:   v[mLiveObjects],
		StackInuse:    v[mHeapStacks],
		StackSys:      v[mHeapStacks] + v[mOSStacks],
		MSpanInuse:    v[mMSpanInuse],
		MSpanSys:      v[mMSpanInuse] + v[mMSpanFree],
		MCacheInuse:   v[mMCacheInuse],
		MCacheSys:     v[mMCacheInuse] + v[mMCacheFree],
		BuckHashSys:   v[mProfilingBuckets],
		GCSys:         v[mMetadataOther],
		OtherSys:      v[mOtherBytes],
		NextGC:        v[mHeapGoal],
		PauseTotalNs:  pauseTotalNs,
		NumGC:         uint32(v[mGCCycles]),
		// LastGC and LastPauseNs have no runtime/metrics equivalent; see the
		// package comment above.
	}
}

// histogramTotalNs approximates total time from a seconds histogram by
// weighting each bucket's count by its midpoint. Buckets with an infinite
// edge are counted at their finite edge, which under-counts the tail — an
// approximation the caller is told about rather than a hidden fudge.
func histogramTotalNs(h *metrics.Float64Histogram) uint64 {
	if h == nil {
		return 0
	}
	var total float64
	for i, count := range h.Counts {
		if count == 0 {
			continue
		}
		lo, hi := h.Buckets[i], h.Buckets[i+1]
		switch {
		case math.IsInf(lo, -1) && math.IsInf(hi, 1):
			continue
		case math.IsInf(lo, -1):
			total += float64(count) * hi
		case math.IsInf(hi, 1):
			total += float64(count) * lo
		default:
			total += float64(count) * (lo + hi) / 2
		}
	}
	return uint64(total * float64(time.Second))
}
