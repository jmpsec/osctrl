import { describe, it, expect } from 'vitest';
import { recomputePostureScore, riskLevelFromScore, controlKey } from './postureScore';
import type { ControlResult, PostureScore } from '$/api/types';

function control(overrides: Partial<ControlResult>): ControlResult {
  return {
    category: 'disk_encryption',
    control_id: 'A.8.24',
    framework: 'ISO27001',
    title: 'Disk encryption',
    description: '',
    status: 'pass',
    severity: 'critical',
    score: 0,
    max_score: 30,
    detail: '',
    ...overrides,
  };
}

function baseScore(controls: ControlResult[]): PostureScore {
  return {
    node_uuid: 'node-1',
    timestamp: '2026-08-21T00:00:00Z',
    total_score: 0,
    risk_level: 'low',
    controls,
    pass_count: 0,
    warn_count: 0,
    fail_count: 0,
  };
}

describe('riskLevelFromScore', () => {
  it('mirrors the Go thresholds', () => {
    expect(riskLevelFromScore(0)).toBe('low');
    expect(riskLevelFromScore(14)).toBe('low');
    expect(riskLevelFromScore(15)).toBe('medium');
    expect(riskLevelFromScore(39)).toBe('medium');
    expect(riskLevelFromScore(40)).toBe('high');
    expect(riskLevelFromScore(69)).toBe('high');
    expect(riskLevelFromScore(70)).toBe('critical');
  });
});

describe('recomputePostureScore', () => {
  it('reproduces the server score when every control is included', () => {
    const controls = [
      control({ control_id: 'A.8.24', status: 'fail', severity: 'critical', score: 30, max_score: 30 }),
      control({ control_id: 'CC6.1', category: 'users', status: 'warn', severity: 'high', score: 5, max_score: 20 }),
      control({ control_id: 'A.8.9', category: 'patches', status: 'pass', severity: 'low', score: 0, max_score: 5 }),
    ];
    const score = baseScore(controls);
    const included = new Set(controls.map(controlKey));

    const result = recomputePostureScore(score, included);

    // earned = 30 + 5 + 0 = 35, possible = 30 + 20 + 5 = 55 -> round(100*35/55) = 64
    expect(result.total_score).toBe(64);
    expect(result.pass_count).toBe(1);
    expect(result.warn_count).toBe(1);
    expect(result.fail_count).toBe(1);
    // A failing critical control always escalates to critical, regardless
    // of the normalized score.
    expect(result.risk_level).toBe('critical');
  });

  it('drops an unchecked control from both the numerator and denominator', () => {
    const controls = [
      control({ control_id: 'A.8.24', status: 'fail', severity: 'critical', score: 30, max_score: 30 }),
      control({ control_id: 'A.8.9', category: 'patches', status: 'pass', severity: 'low', score: 0, max_score: 5 }),
    ];
    const score = baseScore(controls);
    // Uncheck the failing critical control — only the passing low-severity
    // one remains.
    const included = new Set([controlKey(controls[1])]);

    const result = recomputePostureScore(score, included);

    expect(result.total_score).toBe(0);
    expect(result.risk_level).toBe('low');
    expect(result.fail_count).toBe(0);
    expect(result.pass_count).toBe(1);
  });

  it('escalates to high only when the normalized score was low or medium', () => {
    const failingHigh = control({ control_id: 'CC6.1', category: 'users', status: 'fail', severity: 'high', score: 20, max_score: 20 });
    // A single failing high control among nothing else normalizes to 100,
    // which is already >= 70 -> critical is NOT forced (only failing
    // critical severities force critical), but the threshold alone lands
    // on critical here since 100 >= 70.
    const soloResult = recomputePostureScore(baseScore([failingHigh]), new Set([controlKey(failingHigh)]));
    expect(soloResult.risk_level).toBe('critical');

    // Diluted by enough passing weight, the normalized score drops below
    // the high threshold, and the failing-high escalation is what raises
    // it back to "high" rather than leaving it at "medium".
    const passing = control({ control_id: 'A.8.9', category: 'patches', status: 'pass', severity: 'low', score: 0, max_score: 200 });
    const controls = [failingHigh, passing];
    const dilutedResult = recomputePostureScore(baseScore(controls), new Set(controls.map(controlKey)));
    expect(dilutedResult.total_score).toBeLessThan(40);
    expect(dilutedResult.risk_level).toBe('high');
  });

  it('scores an empty selection as 0/low rather than dividing by zero', () => {
    const controls = [control({ status: 'fail', score: 30, max_score: 30 })];
    const result = recomputePostureScore(baseScore(controls), new Set());

    expect(result.total_score).toBe(0);
    expect(result.risk_level).toBe('low');
    expect(result.pass_count).toBe(0);
    expect(result.fail_count).toBe(0);
  });

  it('keys controls by control_id + category, matching the rendered list key', () => {
    const ctrl = control({ control_id: 'A.8.9', category: 'patches' });
    expect(controlKey(ctrl)).toBe('A.8.9patches');
  });
});
