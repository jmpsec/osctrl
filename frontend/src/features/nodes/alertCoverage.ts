import type { AlertRule } from '$/api/alerts';

/**
 * Why a rule reaches this node:
 *   node        — the rule names this UUID (created from "Alert on this node")
 *   environment — an env-scoped rule covering every node in the env
 *   global      — environment_id 0, covering every node in every env
 */
export type AlertScope = 'node' | 'environment' | 'global';

export interface CoveringRule {
  rule: AlertRule;
  scope: AlertScope;
}

/** Sentinel for a global (non-env-scoped) rule row. Mirrors alerts.NoEnvironmentID. */
const GLOBAL_ENV_ID = 0;

/**
 * The enabled rules that would fire for one node, and why.
 *
 * Mirrors pkg/alerts exactly — `ruleApplies` (env 0 is global, otherwise the
 * env must match) plus the node scope check shared by the ingest matcher and
 * the inactive sweep. The UUID comparison is case-sensitive there, so it is
 * case-sensitive here: claiming coverage the backend would not honor is worse
 * than showing none. Disabled rules are excluded because the rule snapshot
 * only loads enabled rows.
 *
 * `envID` undefined means the page has not resolved the node's environment
 * yet, so only global rules can be attributed.
 */
export function nodeAlertCoverage(
  rules: AlertRule[],
  envID: number | undefined,
  uuid: string,
): CoveringRule[] {
  const covering: CoveringRule[] = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const global = rule.environment_id === GLOBAL_ENV_ID;
    if (!global && rule.environment_id !== envID) continue;
    const nodeScope = rule.node_uuid?.trim() ?? '';
    if (nodeScope !== '' && nodeScope !== uuid) continue;
    covering.push({
      rule,
      scope: nodeScope !== '' ? 'node' : global ? 'global' : 'environment',
    });
  }
  // Most specific first: a rule written for this node is the one an operator
  // cares about before the blanket ones.
  const order: Record<AlertScope, number> = { node: 0, environment: 1, global: 2 };
  return covering.sort(
    (a, b) => order[a.scope] - order[b.scope] || a.rule.name.localeCompare(b.rule.name),
  );
}

/** "2 this node · 1 env · 3 global", skipping the scopes with nothing in them. */
export function coverageSummary(covering: CoveringRule[]): string {
  const labels: [AlertScope, string][] = [
    ['node', 'this node'],
    ['environment', 'env'],
    ['global', 'global'],
  ];
  return labels
    .map(([scope, label]) => {
      const n = covering.filter((c) => c.scope === scope).length;
      return n > 0 ? `${n} ${label}` : '';
    })
    .filter(Boolean)
    .join(' · ');
}
