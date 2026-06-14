package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

func TestWriteJSONWritesReportFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	run := RunReport{
		Mode:               "sweep",
		HighestStableStage: 3,
		FirstFailingStage:  4,
		FailureReason:      metrics.VerdictFailedP95,
		Totals:             metrics.Snapshot{Count: 100, FailCount: 3, ErrorRate: 0.03, P95: 1200 * time.Millisecond},
		GeneratedAt:        time.Unix(1_700_000_000, 0).UTC(),
	}

	if err := WriteJSON(path, run); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}
	if !strings.Contains(string(raw), "\"highest_stable_stage\": 3") {
		t.Fatalf("unexpected report body: %s", string(raw))
	}
}

func TestSummaryIncludesLimitVerdict(t *testing.T) {
	t.Parallel()

	summary := Summary(RunReport{
		Mode:               "sweep",
		HighestStableStage: 3,
		FirstFailingStage:  4,
		FailureReason:      metrics.VerdictFailedP95,
	})

	if !strings.Contains(summary, "highest stable stage 3") {
		t.Fatalf("unexpected summary: %s", summary)
	}
	if !strings.Contains(summary, "first failing stage 4") {
		t.Fatalf("unexpected summary: %s", summary)
	}
}
