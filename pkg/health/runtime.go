package health

import (
	"runtime"
	"time"
)

// RuntimeStats is the Go runtime detail shown per service. Field set mirrors
// what an operator expects from runtime.MemStats.
type RuntimeStats struct {
	UptimeSeconds int64  `json:"uptime_seconds"`
	Goroutines    int    `json:"goroutines"`
	Alloc         uint64 `json:"alloc"`
	TotalAlloc    uint64 `json:"total_alloc"`
	Sys           uint64 `json:"sys"`
	Lookups       uint64 `json:"lookups"`
	Mallocs       uint64 `json:"mallocs"`
	Frees         uint64 `json:"frees"`
	HeapAlloc     uint64 `json:"heap_alloc"`
	HeapSys       uint64 `json:"heap_sys"`
	HeapIdle      uint64 `json:"heap_idle"`
	HeapInuse     uint64 `json:"heap_inuse"`
	HeapReleased  uint64 `json:"heap_released"`
	HeapObjects   uint64 `json:"heap_objects"`
	StackInuse    uint64 `json:"stack_inuse"`
	StackSys      uint64 `json:"stack_sys"`
	MSpanInuse    uint64 `json:"mspan_inuse"`
	MSpanSys      uint64 `json:"mspan_sys"`
	MCacheInuse   uint64 `json:"mcache_inuse"`
	MCacheSys     uint64 `json:"mcache_sys"`
	BuckHashSys   uint64 `json:"buck_hash_sys"`
	GCSys         uint64 `json:"gc_sys"`
	OtherSys      uint64 `json:"other_sys"`
	NextGC        uint64 `json:"next_gc"`
	LastGC        int64  `json:"last_gc_unix_ms"`
	PauseTotalNs  uint64 `json:"pause_total_ns"`
	LastPauseNs   uint64 `json:"last_pause_ns"`
	NumGC         uint32 `json:"num_gc"`
}

// Snapshot reads the current runtime state.
//
// runtime.ReadMemStats STOPS THE WORLD. The pause is short (tens of µs) and
// harmless when an operator loads a page, which is the only thing that calls
// this. Do not put it on a ticker inside osctrl-tls — the heartbeat carries
// NumGoroutine and existing atomics instead, and runtime/metrics (no STW) is
// the tool if periodic memory sampling is ever wanted.
func Snapshot(startedAt time.Time) RuntimeStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var lastPause uint64
	if m.NumGC > 0 {
		lastPause = m.PauseNs[(m.NumGC+255)%256]
	}
	var lastGC int64
	if m.LastGC > 0 {
		lastGC = int64(m.LastGC / uint64(time.Millisecond))
	}

	return RuntimeStats{
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		Alloc:         m.Alloc,
		TotalAlloc:    m.TotalAlloc,
		Sys:           m.Sys,
		Lookups:       m.Lookups,
		Mallocs:       m.Mallocs,
		Frees:         m.Frees,
		HeapAlloc:     m.HeapAlloc,
		HeapSys:       m.HeapSys,
		HeapIdle:      m.HeapIdle,
		HeapInuse:     m.HeapInuse,
		HeapReleased:  m.HeapReleased,
		HeapObjects:   m.HeapObjects,
		StackInuse:    m.StackInuse,
		StackSys:      m.StackSys,
		MSpanInuse:    m.MSpanInuse,
		MSpanSys:      m.MSpanSys,
		MCacheInuse:   m.MCacheInuse,
		MCacheSys:     m.MCacheSys,
		BuckHashSys:   m.BuckHashSys,
		GCSys:         m.GCSys,
		OtherSys:      m.OtherSys,
		NextGC:        m.NextGC,
		LastGC:        lastGC,
		PauseTotalNs:  m.PauseTotalNs,
		LastPauseNs:   lastPause,
		NumGC:         m.NumGC,
	}
}
