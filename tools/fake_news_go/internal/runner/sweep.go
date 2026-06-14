package runner

import (
	"context"

	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

type SweepResult struct {
	HighestStableStage int
	FirstFailingStage  int
	FailureReason      metrics.Verdict
}

type SweepController struct {
	Thresholds metrics.Thresholds
}

func (c SweepController) EvaluateStages(ctx context.Context, stages []metrics.Snapshot) SweepResult {
	result := SweepResult{
		HighestStableStage: -1,
		FirstFailingStage:  -1,
		FailureReason:      metrics.VerdictStable,
	}

	for i, stage := range stages {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		evaluation := metrics.Evaluate(stage, c.Thresholds)
		if evaluation.Failed {
			result.FirstFailingStage = i
			result.FailureReason = evaluation.Verdict
			return result
		}
		result.HighestStableStage = i
	}

	return result
}
