package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

type RunReport struct {
	Mode               string           `json:"mode"`
	HighestStableStage int              `json:"highest_stable_stage"`
	FirstFailingStage  int              `json:"first_failing_stage"`
	FailureReason      metrics.Verdict  `json:"failure_reason"`
	Totals             metrics.Snapshot `json:"totals"`
	GeneratedAt        time.Time        `json:"generated_at"`
}

func WriteJSON(path string, run RunReport) error {
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, raw, 0644)
}

func Summary(run RunReport) string {
	return fmt.Sprintf(
		"mode %s: highest stable stage %d, first failing stage %d, verdict %s",
		run.Mode,
		run.HighestStableStage,
		run.FirstFailingStage,
		run.FailureReason,
	)
}
