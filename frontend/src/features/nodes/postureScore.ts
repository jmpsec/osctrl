import type { ControlResult, PostureScore } from '$/api/types';

// ---------------------------------------------------------------------------
// Client-side recompute of the aggregate posture score over a *subset* of
// the controls the server already evaluated — the posture tab's per-check
// "what if I ignore this" toggle.
//
// This mirrors only the aggregation math in pkg/posture/scoring.go
// (ScoreCalculator.Score's earned/possible normalization and riskLevel's
// escalation), not the individual rule Evaluate() functions — those already
// ran server-side and their outcome (status, score, max_score, severity) is
// on each ControlResult. Recomputing here never re-derives pass/warn/fail
// from raw posture rows, so there is no risk of drifting from the rules.
//
// Keep in sync with pkg/posture/scoring.go if either file changes:
//   - RiskLevelFromScore's thresholds (70/40/15)
//   - riskLevel's critical/high escalation on a failing control
// ---------------------------------------------------------------------------

/** Mirrors posture.RiskLevelFromScore. */
export function riskLevelFromScore(score: number): string {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  return 'low';
}

/** Mirrors posture.riskLevel's escalation by the worst failing control. */
function escalatedRiskLevel(score: number, controls: ControlResult[]): string {
  let level = riskLevelFromScore(score);
  for (const c of controls) {
    if (c.status !== 'fail') continue;
    if (c.severity === 'critical') return 'critical';
    if (c.severity === 'high' && (level === 'low' || level === 'medium')) {
      level = 'high';
    }
  }
  return level;
}

/** Identifies a control within a PostureScore — matches the React list key. */
export function controlKey(ctrl: ControlResult): string {
  return ctrl.control_id + ctrl.category;
}

/**
 * Recomputes total_score, risk_level and the pass/warn/fail counts from
 * only the controls whose key is in `included`. Passing the full set of
 * keys reproduces the server's own PostureScore exactly — earned and
 * max_score are read straight off each ControlResult, never re-derived.
 */
export function recomputePostureScore(
  base: PostureScore,
  included: ReadonlySet<string>,
): PostureScore {
  const controls = (base.controls ?? []).filter((c) => included.has(controlKey(c)));

  let earned = 0;
  let possible = 0;
  let passCount = 0;
  let warnCount = 0;
  let failCount = 0;
  for (const c of controls) {
    earned += c.score;
    possible += c.max_score;
    if (c.status === 'pass') passCount++;
    else if (c.status === 'warn') warnCount++;
    else if (c.status === 'fail') failCount++;
  }

  const totalScore = possible > 0 ? Math.round((100 * earned) / possible) : 0;

  return {
    ...base,
    total_score: totalScore,
    risk_level: escalatedRiskLevel(totalScore, controls),
    pass_count: passCount,
    warn_count: warnCount,
    fail_count: failCount,
  };
}
