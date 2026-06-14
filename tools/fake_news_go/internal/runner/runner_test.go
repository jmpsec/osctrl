package runner

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

func TestSweepStopsOnFirstFailingStage(t *testing.T) {
	t.Parallel()

	ctrl := SweepController{
		Thresholds: metrics.Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
	}

	stages := []metrics.Snapshot{
		{Count: 100, FailCount: 0, ErrorRate: 0, P95: 300 * time.Millisecond},
		{Count: 100, FailCount: 0, ErrorRate: 0, P95: 1200 * time.Millisecond},
		{Count: 100, FailCount: 10, ErrorRate: 0.10, P95: 1300 * time.Millisecond},
	}

	result := ctrl.EvaluateStages(context.Background(), stages)

	if result.HighestStableStage != 0 {
		t.Fatalf("expected highest stable stage 0, got %d", result.HighestStableStage)
	}
	if result.FirstFailingStage != 1 {
		t.Fatalf("expected first failing stage 1, got %d", result.FirstFailingStage)
	}
	if result.FailureReason != metrics.VerdictFailedP95 {
		t.Fatalf("expected p95 failure, got %q", result.FailureReason)
	}
}

func TestSweepMarksAllStableWhenThresholdsAreNotCrossed(t *testing.T) {
	t.Parallel()

	ctrl := SweepController{
		Thresholds: metrics.Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
	}

	stages := []metrics.Snapshot{
		{Count: 100, FailCount: 0, ErrorRate: 0, P95: 200 * time.Millisecond},
		{Count: 100, FailCount: 1, ErrorRate: 0.01, P95: 400 * time.Millisecond},
	}

	result := ctrl.EvaluateStages(context.Background(), stages)

	if result.HighestStableStage != 1 {
		t.Fatalf("expected highest stable stage 1, got %d", result.HighestStableStage)
	}
	if result.FirstFailingStage != -1 {
		t.Fatalf("expected no failing stage, got %d", result.FirstFailingStage)
	}
	if result.FailureReason != metrics.VerdictStable {
		t.Fatalf("expected stable verdict, got %q", result.FailureReason)
	}
}
