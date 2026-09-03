import { describe, it, expect } from 'vitest';
import type { AlertRule } from '$/api/alerts';
import { nodeAlertCoverage, coverageSummary } from './alertCoverage';

function rule(over: Partial<AlertRule>): AlertRule {
  return {
    id: 1,
    created_at: '',
    updated_at: '',
    name: 'r',
    environment_id: 1,
    source: 'result_log',
    node_uuid: '',
    match_type: 'substring',
    match_field: '',
    match_value: 'x',
    status_severity: 'any',
    cooldown_minutes: 0,
    channel_ids: [],
    enabled: true,
    info: '',
    ...over,
  };
}

const UUID = 'ABC12345-0000-0000-0000-000000000001';

describe('nodeAlertCoverage', () => {
  it('attributes each covering rule to its scope, most specific first', () => {
    const covering = nodeAlertCoverage(
      [
        rule({ id: 1, name: 'global-rule', environment_id: 0 }),
        rule({ id: 2, name: 'env-rule', environment_id: 1 }),
        rule({ id: 3, name: 'node-rule', environment_id: 1, node_uuid: UUID }),
      ],
      1,
      UUID,
    );
    expect(covering.map((c) => [c.rule.name, c.scope])).toEqual([
      ['node-rule', 'node'],
      ['env-rule', 'environment'],
      ['global-rule', 'global'],
    ]);
  });

  it('excludes other environments, other nodes, and disabled rules', () => {
    const covering = nodeAlertCoverage(
      [
        rule({ id: 1, name: 'other-env', environment_id: 2 }),
        rule({ id: 2, name: 'other-node', environment_id: 1, node_uuid: 'SOME-OTHER-NODE' }),
        rule({ id: 3, name: 'switched-off', environment_id: 1, enabled: false }),
        rule({ id: 4, name: 'off-and-global', environment_id: 0, enabled: false }),
      ],
      1,
      UUID,
    );
    expect(covering).toEqual([]);
  });

  it('matches a node scope the backend would match, and not one it would not', () => {
    // pkg/alerts compares the scope byte-for-byte, so a lowercased UUID does
    // not cover an uppercase node — do not claim it does.
    const rules = [rule({ node_uuid: UUID.toLowerCase(), environment_id: 1 })];
    expect(nodeAlertCoverage(rules, 1, UUID)).toEqual([]);
    // Whitespace is trimmed on the way in, matching TrimSpace on the server.
    expect(nodeAlertCoverage([rule({ node_uuid: ` ${UUID} `, environment_id: 1 })], 1, UUID)).toHaveLength(1);
  });

  it('attributes only global rules before the environment is resolved', () => {
    const covering = nodeAlertCoverage(
      [
        rule({ id: 1, name: 'global-rule', environment_id: 0 }),
        rule({ id: 2, name: 'env-rule', environment_id: 1 }),
      ],
      undefined,
      UUID,
    );
    expect(covering.map((c) => c.rule.name)).toEqual(['global-rule']);
  });
});

describe('coverageSummary', () => {
  it('lists only the scopes present', () => {
    const covering = nodeAlertCoverage(
      [
        rule({ id: 1, environment_id: 0, name: 'g' }),
        rule({ id: 2, environment_id: 1, node_uuid: UUID, name: 'n1' }),
        rule({ id: 3, environment_id: 1, node_uuid: UUID, name: 'n2' }),
      ],
      1,
      UUID,
    );
    expect(coverageSummary(covering)).toBe('2 this node · 1 global');
  });

  it('is empty with no coverage', () => {
    expect(coverageSummary([])).toBe('');
  });
});
