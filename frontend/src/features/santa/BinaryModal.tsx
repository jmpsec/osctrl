import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { checkSantaRisk, getSantaBinary, santaQueryKey, type SantaBinary } from '$/api/santa';
import { Button } from '$/components/atoms/Button';
import { Skeleton } from '$/components/data/Skeleton';
import { ModalShell } from '$/components/feedback/ModalShell';
import { useLocale } from '$/i18n/useLocale';
import { RiskBadge } from './RiskBadge';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

const SUB = 'text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]';
const HEADING = 'text-sm font-semibold text-[color:var(--text-1)]';

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div>
      <dt className="text-xs text-[color:var(--text-3)]">{label}</dt>
      <dd className={`${mono ? MONO : ''} text-sm text-[color:var(--text-1)] [overflow-wrap:anywhere]`}>{value}</dd>
    </div>
  );
}

/**
 * Context for deciding on a rule: who signed a binary, where it ran and which
 * rules already name it. Everything shown is reported by Santa clients, so it
 * is rendered as React text only.
 */
export function BinaryModal({ env, sha256, onClose }: {
  env: string;
  sha256: string;
  /** Must be stable (useCallback): ModalShell re-runs its focus effect on change. */
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const qc = useQueryClient();
  const key = santaQueryKey(env, 'binaries', sha256);
  const binary = useQuery({ queryKey: key, queryFn: () => getSantaBinary(env, sha256), retry: false });
  const check = useMutation({
    mutationFn: () => checkSantaRisk(env, sha256),
    onSuccess: (risk) => {
      qc.setQueryData<SantaBinary>(key, (prev) => (prev ? { ...prev, risk } : prev));
      void qc.invalidateQueries({ queryKey: santaQueryKey(env, 'requests') });
    },
  });
  const b = binary.data;
  const chain = b?.signing_chain ?? [];
  const rules = b?.rules ?? [];
  const when = (v: string) => formatDateTime(new Date(v));

  return (
    <ModalShell title={t('santa.binary.title')} titleId="santa-binary-title" onClose={onClose} panelClassName="max-w-2xl">
      {binary.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : binary.isError || !b ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(binary.error) ?? t('santa.loadError')}</p>
      ) : (
        <div className="space-y-4">
          <dl className="grid gap-2 sm:grid-cols-2">
            <Field label={t('santa.file')} value={b.file_name} />
            <Field label="SHA-256" value={b.sha256} mono />
            <Field label="Team ID" value={b.team_id} mono />
            <Field label="Signing ID" value={b.signing_id} mono />
            <Field label="CDHash" value={b.cd_hash} mono />
            <Field label={t('santa.binary.bundle')} value={[b.bundle_name, b.bundle_version].filter(Boolean).join(' ') || b.bundle_id} />
          </dl>
          {b.file_path && <div className={SUB}>{b.file_path}</div>}
          {b.bundle_name && b.bundle_id && <div className={`${MONO} ${SUB}`}>{b.bundle_id}</div>}
          {b.bundle_path && <div className={SUB}>{b.bundle_path}</div>}

          <dl className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            <Field label={t('santa.binary.firstSeen')} value={when(b.first_seen)} />
            <Field label={t('santa.binary.lastSeen')} value={when(b.last_seen)} />
            <Field label={t('santa.tabMachines')} value={String(b.machines)} />
            <Field label={t('santa.binary.executions')} value={String(b.events)} />
            <Field label={t('santa.binary.blocked')} value={String(b.blocked)} />
          </dl>
          <p className={SUB}>{t('santa.binary.retention')}</p>

          {b.risk && (
            <section className="space-y-1">
              <div className="flex items-center gap-2">
                <h3 className={HEADING}>{t('santa.risk.title')}</h3>
                <RiskBadge risk={b.risk} />
                <Button size="sm" variant="ghost" className="ms-auto" disabled={check.isPending} onClick={() => check.mutate()}>
                  {t('santa.risk.checkNow')}
                </Button>
              </div>
              {(b.risk.checks ?? []).map((c) => (
                <div key={c.check} className={SUB}>{c.check}: {t(`santa.risk.verdicts.${c.verdict}`)}{c.detail && ` — ${c.detail}`}</div>
              ))}
              {check.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(check.error)}</p>}
            </section>
          )}

          <section className="space-y-1">
            <h3 className={HEADING}>{t('santa.binary.signingChain')}</h3>
            {chain.length === 0 ? (
              <p className={SUB}>{t('santa.binary.unsigned')}</p>
            ) : (
              <ol className="space-y-1.5">
                {chain.map((c, i) => (
                  <li key={`${c.sha256}-${i}`} className="text-sm">
                    <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{c.cn || c.sha256}</div>
                    <div className={SUB}>{[c.org, c.ou].filter(Boolean).join(' · ')}</div>
                    <div className={`${MONO} ${SUB}`}>{c.sha256}</div>
                    <div className={SUB}>{when(c.valid_from)} – {when(c.valid_until)}</div>
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="space-y-1">
            <h3 className={HEADING}>{t('santa.binary.rules')}</h3>
            {rules.length === 0 ? (
              <p className={SUB}>{t('santa.binary.noRules')}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className={TABLE}>
                  <thead>
                    <tr className="border-b border-[color:var(--border)]">
                      <th scope="col" className={TH}>{t('santa.ruleType')}</th>
                      <th scope="col" className={TH}>{t('santa.policy')}</th>
                      <th scope="col" className={TH}>{t('santa.scope')}</th>
                      <th scope="col" className={TH}>{t('santa.scopeValue')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((r) => (
                      <tr key={r.id} className={ROW}>
                        <td className={TD}>{r.rule_type}</td>
                        <td className={TD}>{r.policy}</td>
                        <td className={TD}>{t(`santa.scopes.${r.scope}`)}</td>
                        <td className={`${TD} ${MONO}`}>{r.scope_value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}
    </ModalShell>
  );
}
