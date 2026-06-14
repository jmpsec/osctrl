package tui

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

func TestNewDashboardModelIncludesDenseMetrics(t *testing.T) {
	t.Parallel()

	model := NewDashboardModel(ViewModel{
		Mode:    "sweep",
		Verdict: metrics.VerdictFailedP95,
		Dashboard: metrics.NewDashboardSnapshot(
			metrics.Snapshot{Count: 100, FailCount: 1, ErrorRate: 0.01, P95: 900 * time.Millisecond, P99: 950 * time.Millisecond},
			map[string]metrics.Snapshot{
				"enroll":      {Count: 10, ErrorRate: 0, P95: 50 * time.Millisecond},
				"query-write": {Count: 40, ErrorRate: 0.02, P95: 900 * time.Millisecond},
			},
			map[string]metrics.Snapshot{
				"/env/enroll": {Count: 10, ErrorRate: 0, P95: 50 * time.Millisecond},
				"/env/write":  {Count: 40, ErrorRate: 0.02, P95: 900 * time.Millisecond},
			},
			metrics.SweepState{Stage: 2, HighestStableStage: 1, TargetNodes: 50, SettleRemaining: 4 * time.Second, SampleRemaining: 9 * time.Second},
		),
		Thresholds: metrics.Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
		ReportPath: "/tmp/report.json",
	})

	if len(model.OperationRows) != 3 {
		t.Fatalf("expected header plus 2 operation rows, got %d", len(model.OperationRows))
	}
	if len(model.EndpointRows) != 3 {
		t.Fatalf("expected header plus 2 endpoint rows, got %d", len(model.EndpointRows))
	}
	if model.Header == "" || model.Sweep == "" || model.Summary == "" || model.Footer == "" {
		t.Fatalf("expected all major sections to be populated: %+v", model)
	}
	if model.HealthLabel == "" || model.ErrorGaugeLabel == "" || model.LatencyGaugeLabel == "" {
		t.Fatalf("expected gauge labels to be populated: %+v", model)
	}
	if model.OperationSeverity[2] != SeverityWarn {
		t.Fatalf("expected hot operation row to be warned, got %+v", model.OperationSeverity)
	}
	if model.EndpointSeverity[2] != SeverityWarn {
		t.Fatalf("expected hot endpoint row to be warned, got %+v", model.EndpointSeverity)
	}
}

func TestNewDashboardModelMarksFailedVerdictCritical(t *testing.T) {
	t.Parallel()

	model := NewDashboardModel(ViewModel{
		Mode:    "sweep",
		Verdict: metrics.VerdictFailedErrorRate,
		Dashboard: metrics.NewDashboardSnapshot(
			metrics.Snapshot{Count: 100, FailCount: 10, ErrorRate: 0.10, P95: 1500 * time.Millisecond, P99: 2 * time.Second},
			map[string]metrics.Snapshot{},
			map[string]metrics.Snapshot{},
			metrics.SweepState{},
		),
		Thresholds: metrics.Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
		ReportPath: "/tmp/report.json",
	})

	if model.HealthSeverity != SeverityCritical {
		t.Fatalf("expected critical health severity, got %q", model.HealthSeverity)
	}
}

func TestShouldQuitEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id   string
		want bool
	}{
		{id: "q", want: true},
		{id: "Q", want: true},
		{id: "<C-c>", want: true},
		{id: "x", want: false},
		{id: "<Resize>", want: false},
	}

	for _, tt := range tests {
		if got := ShouldQuitEvent(tt.id); got != tt.want {
			t.Fatalf("ShouldQuitEvent(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}
