package metrics

import (
	"testing"
	"time"
)

func TestRecorderSnapshotCalculatesStats(t *testing.T) {
	t.Parallel()

	recorder := NewRecorder(10)
	recorder.Record(10*time.Millisecond, true)
	recorder.Record(20*time.Millisecond, true)
	recorder.Record(30*time.Millisecond, false)
	recorder.Record(40*time.Millisecond, true)
	recorder.Record(50*time.Millisecond, true)

	snapshot := recorder.Snapshot()

	if snapshot.Count != 5 {
		t.Fatalf("expected count 5, got %d", snapshot.Count)
	}
	if snapshot.SuccessCount != 4 {
		t.Fatalf("expected success count 4, got %d", snapshot.SuccessCount)
	}
	if snapshot.FailCount != 1 {
		t.Fatalf("expected fail count 1, got %d", snapshot.FailCount)
	}
	if snapshot.ErrorRate != 0.2 {
		t.Fatalf("expected error rate 0.2, got %v", snapshot.ErrorRate)
	}
	if snapshot.Min != 10*time.Millisecond || snapshot.Max != 50*time.Millisecond {
		t.Fatalf("unexpected min/max: %v/%v", snapshot.Min, snapshot.Max)
	}
	if snapshot.Avg != 30*time.Millisecond {
		t.Fatalf("expected avg 30ms, got %v", snapshot.Avg)
	}
	if snapshot.P95 != 50*time.Millisecond || snapshot.P99 != 50*time.Millisecond {
		t.Fatalf("unexpected percentiles: p95=%v p99=%v", snapshot.P95, snapshot.P99)
	}
}

func TestRecorderCapsRetainedSamples(t *testing.T) {
	t.Parallel()

	recorder := NewRecorder(3)
	recorder.Record(10*time.Millisecond, true)
	recorder.Record(20*time.Millisecond, true)
	recorder.Record(30*time.Millisecond, true)
	recorder.Record(40*time.Millisecond, true)
	recorder.Record(50*time.Millisecond, true)

	if got := recorder.RetainedSamples(); got != 3 {
		t.Fatalf("expected 3 retained samples, got %d", got)
	}

	snapshot := recorder.Snapshot()
	if snapshot.Count != 5 {
		t.Fatalf("expected total count 5, got %d", snapshot.Count)
	}
}

func TestEvaluateFailsOnErrorRate(t *testing.T) {
	t.Parallel()

	evaluation := Evaluate(
		Snapshot{Count: 10, FailCount: 1, ErrorRate: 0.10, P95: 250 * time.Millisecond},
		Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
	)

	if !evaluation.Failed {
		t.Fatal("expected evaluation to fail")
	}
	if evaluation.Verdict != VerdictFailedErrorRate {
		t.Fatalf("expected error rate verdict, got %q", evaluation.Verdict)
	}
}

func TestEvaluateFailsOnP95(t *testing.T) {
	t.Parallel()

	evaluation := Evaluate(
		Snapshot{Count: 10, ErrorRate: 0.01, P95: 1500 * time.Millisecond},
		Thresholds{MaxErrorRate: 0.02, MaxP95: time.Second},
	)

	if !evaluation.Failed {
		t.Fatal("expected evaluation to fail")
	}
	if evaluation.Verdict != VerdictFailedP95 {
		t.Fatalf("expected p95 verdict, got %q", evaluation.Verdict)
	}
}

func TestDashboardSnapshotSortsOperationsAndEndpoints(t *testing.T) {
	t.Parallel()

	snapshot := NewDashboardSnapshot(
		Snapshot{Count: 10, FailCount: 1, ErrorRate: 0.10, P95: 250 * time.Millisecond},
		map[string]Snapshot{
			"query-write": {Count: 2, P95: 400 * time.Millisecond},
			"enroll":      {Count: 8, P95: 100 * time.Millisecond},
		},
		map[string]Snapshot{
			"/write":  {Count: 2, P95: 400 * time.Millisecond},
			"/enroll": {Count: 8, P95: 100 * time.Millisecond},
		},
		SweepState{Stage: 2, HighestStableStage: 1, TargetNodes: 50},
	)

	if len(snapshot.Operations) != 2 || snapshot.Operations[0].Name != "enroll" || snapshot.Operations[1].Name != "query-write" {
		t.Fatalf("unexpected operation ordering: %+v", snapshot.Operations)
	}
	if len(snapshot.Endpoints) != 2 || snapshot.Endpoints[0].Name != "/enroll" || snapshot.Endpoints[1].Name != "/write" {
		t.Fatalf("unexpected endpoint ordering: %+v", snapshot.Endpoints)
	}
	if snapshot.Sweep.TargetNodes != 50 {
		t.Fatalf("unexpected sweep state: %+v", snapshot.Sweep)
	}
}
