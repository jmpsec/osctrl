package runner

import "github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"

type SnapshotSource interface {
	Snapshot() metrics.Snapshot
}

type SteadyRunner struct {
	source SnapshotSource
}

func NewSteadyRunner(source SnapshotSource) *SteadyRunner {
	return &SteadyRunner{source: source}
}

func (r *SteadyRunner) Snapshot() metrics.Snapshot {
	if r == nil || r.source == nil {
		return metrics.Snapshot{}
	}
	return r.source.Snapshot()
}
