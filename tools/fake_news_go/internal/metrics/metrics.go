package metrics

import (
	"sort"
	"sync"
	"time"
)

const defaultRetention = 1000

type Snapshot struct {
	Count        int64
	SuccessCount int64
	FailCount    int64
	ErrorRate    float64
	Min          time.Duration
	Max          time.Duration
	Avg          time.Duration
	P95          time.Duration
	P99          time.Duration
}

type NamedSnapshot struct {
	Name string
	Snapshot
}

type SweepState struct {
	Stage              int
	HighestStableStage int
	TargetNodes        int
	SettleRemaining    time.Duration
	SampleRemaining    time.Duration
}

type DashboardSnapshot struct {
	Totals     Snapshot
	Operations []NamedSnapshot
	Endpoints  []NamedSnapshot
	Sweep      SweepState
}

type Recorder struct {
	mu        sync.RWMutex
	latencies []time.Duration
	total     time.Duration
	min       time.Duration
	max       time.Duration
	count     int64
	success   int64
	fail      int64
	retention int
}

func NewRecorder(retention int) *Recorder {
	if retention <= 0 {
		retention = defaultRetention
	}
	return &Recorder{retention: retention}
}

func (r *Recorder) Record(latency time.Duration, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.latencies = append(r.latencies, latency)
	r.count++
	r.total += latency

	if success {
		r.success++
	} else {
		r.fail++
	}

	if r.count == 1 {
		r.min = latency
		r.max = latency
	} else {
		if latency < r.min {
			r.min = latency
		}
		if latency > r.max {
			r.max = latency
		}
	}

	if len(r.latencies) > r.retention {
		r.latencies = r.latencies[len(r.latencies)-r.retention:]
	}
}

func (r *Recorder) RetainedSamples() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.latencies)
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return Snapshot{}
	}

	snapshot := Snapshot{
		Count:        r.count,
		SuccessCount: r.success,
		FailCount:    r.fail,
		Min:          r.min,
		Max:          r.max,
		Avg:          r.total / time.Duration(r.count),
	}
	if r.count > 0 {
		snapshot.ErrorRate = float64(r.fail) / float64(r.count)
	}

	if len(r.latencies) == 0 {
		return snapshot
	}

	sortedLatencies := make([]time.Duration, len(r.latencies))
	copy(sortedLatencies, r.latencies)
	sort.Slice(sortedLatencies, func(i, j int) bool {
		return sortedLatencies[i] < sortedLatencies[j]
	})

	p95Idx := percentileIndex(len(sortedLatencies), 0.95)
	p99Idx := percentileIndex(len(sortedLatencies), 0.99)
	snapshot.P95 = sortedLatencies[p95Idx]
	snapshot.P99 = sortedLatencies[p99Idx]

	return snapshot
}

func percentileIndex(size int, ratio float64) int {
	if size <= 1 {
		return 0
	}

	idx := int(float64(size) * ratio)
	if idx >= size {
		idx = size - 1
	}
	return idx
}

func NewDashboardSnapshot(totals Snapshot, operations map[string]Snapshot, endpoints map[string]Snapshot, sweep SweepState) DashboardSnapshot {
	out := DashboardSnapshot{
		Totals: totals,
		Sweep:  sweep,
	}

	for name, snapshot := range operations {
		out.Operations = append(out.Operations, NamedSnapshot{Name: name, Snapshot: snapshot})
	}
	for name, snapshot := range endpoints {
		out.Endpoints = append(out.Endpoints, NamedSnapshot{Name: name, Snapshot: snapshot})
	}

	sort.Slice(out.Operations, func(i, j int) bool {
		return out.Operations[i].Name < out.Operations[j].Name
	})
	sort.Slice(out.Endpoints, func(i, j int) bool {
		return out.Endpoints[i].Name < out.Endpoints[j].Name
	})

	return out
}

type Thresholds struct {
	MaxErrorRate float64
	MaxP95       time.Duration
}

type Verdict string

const (
	VerdictStable          Verdict = "stable"
	VerdictFailedErrorRate Verdict = "failed_error_rate"
	VerdictFailedP95       Verdict = "failed_p95"
)

type Evaluation struct {
	Verdict Verdict
	Failed  bool
}

func Evaluate(snapshot Snapshot, thresholds Thresholds) Evaluation {
	if thresholds.MaxErrorRate > 0 && snapshot.ErrorRate > thresholds.MaxErrorRate {
		return Evaluation{
			Verdict: VerdictFailedErrorRate,
			Failed:  true,
		}
	}
	if thresholds.MaxP95 > 0 && snapshot.P95 > thresholds.MaxP95 {
		return Evaluation{
			Verdict: VerdictFailedP95,
			Failed:  true,
		}
	}

	return Evaluation{Verdict: VerdictStable}
}
