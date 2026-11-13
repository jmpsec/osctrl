import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import {
  createSantaRule,
  deleteSantaRule,
  listSantaRules,
  santaQueryKey,
  updateSantaRule,
  SANTA_POLICIES,
  SANTA_RULE_TYPES,
  SANTA_SCOPES,
  type SantaRule,
  type SantaRuleInput,
} from '$/api/santa';
import { ApiError } from '$/api/client';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { EmptyState } from '$/components/data/EmptyState';
import { SkeletonRow } from '$/components/data/Skeleton';
import { ModalShell } from '$/components/feedback/ModalShell';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

export const EMPTY_RULE: SantaRuleInput = {
  identifier: '',
  rule_type: 'BINARY',
  policy: 'ALLOWLIST',
  cel_expr: '',
  custom_msg: '',
  custom_url: '',
  scope: 'env',
  scope_value: '',
};

/** Form state; id is set when editing an existing rule. */
export type RuleDraft = SantaRuleInput & { id?: number };

function toDraft(r: SantaRule): RuleDraft {
  const { id, identifier, rule_type, policy, cel_expr, custom_msg, custom_url, scope, scope_value } = r;
  return { id, identifier, rule_type, policy, cel_expr, custom_msg, custom_url, scope, scope_value };
}

const SELECT =
  'h-8 w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]';

export function RulesTab({ env, onAdd, onEdit }: { env: string; onAdd: () => void; onEdit: (r: RuleDraft) => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: santaQueryKey(env, 'rules'), queryFn: () => listSantaRules(env) });
  const remove = useMutation({
    mutationFn: (id: number) => deleteSantaRule(env, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: santaQueryKey(env, 'rules') }),
  });
  const rows = rules.data ?? [];

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button size="sm" onClick={onAdd}>{t('santa.addRule')}</Button>
      </div>
      {remove.isError && (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(remove.error) ?? t('santa.deleteError')}</p>
      )}
      <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
        {rules.isLoading ? (
          <table className={TABLE}><tbody>{Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}</tbody></table>
        ) : rules.isError ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.loadError')} description={errorText(rules.error)} />
        ) : rows.length === 0 ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.noRules')} />
        ) : (
          <div className="overflow-x-auto">
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                  <th scope="col" className={TH}>{t('santa.identifier')}</th>
                  <th scope="col" className={TH}>{t('santa.ruleType')}</th>
                  <th scope="col" className={TH}>{t('santa.policy')}</th>
                  <th scope="col" className={TH}>{t('santa.scope')}</th>
                  <th scope="col" className={TH}>{t('santa.createdBy')}</th>
                  <th scope="col" className={TH}><span className="sr-only">{t('santa.actions')}</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className={ROW}>
                    <td className={`${TD} ${MONO} text-[color:var(--text-1)]`}>{r.identifier}</td>
                    <td className={TD}>{r.rule_type}</td>
                    <td className={TD}>{r.policy}</td>
                    <td className={TD}>{r.scope === 'env' ? r.scope : `${r.scope}: ${r.scope_value}`}</td>
                    <td className={TD}>{r.created_by}</td>
                    <td className={`${TD} whitespace-nowrap text-end`}>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="me-2"
                        aria-label={`${t('santa.edit')} ${r.identifier}`}
                        onClick={() => onEdit(toDraft(r))}
                      >
                        {t('santa.edit')}
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={remove.isPending}
                        aria-label={`${t('santa.delete')} ${r.identifier}`}
                        onClick={() => {
                          if (confirm(t('santa.confirmDelete', { identifier: r.identifier }))) remove.mutate(r.id);
                        }}
                      >
                        {t('santa.delete')}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export function RuleFormModal({
  env,
  initial,
  onClose,
}: {
  env: string;
  initial: RuleDraft;
  /** Must be stable (useCallback): ModalShell re-runs its focus effect on change. */
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { id, ...rest } = initial;
  const [form, setForm] = useState<SantaRuleInput>(rest);
  const save = useMutation({
    // Backstop: fields hidden by the current scope/policy are never posted.
    mutationFn: () => {
      const body = {
        ...form,
        scope_value: form.scope === 'env' ? '' : form.scope_value,
        cel_expr: form.policy === 'CEL' ? form.cel_expr : '',
      };
      return id === undefined ? createSantaRule(env, body) : updateSantaRule(env, id, body);
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: santaQueryKey(env, 'rules') });
      onClose();
    },
  });
  const set = <K extends keyof SantaRuleInput>(key: K, value: SantaRuleInput[K]) => setForm((f) => ({ ...f, [key]: value }));
  const error = save.error;
  const message = error instanceof ApiError && error.status === 409 ? t('santa.ruleExists') : errorText(error);

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <ModalShell title={id === undefined ? t('santa.addRule') : t('santa.editRule')} titleId="santa-rule-title" onClose={onClose} bodyClassName="max-h-[70vh] overflow-y-auto">
      <form onSubmit={submit} className="space-y-3">
        <div>
          <Label htmlFor="santa-identifier" required>{t('santa.identifier')}</Label>
          <Input id="santa-identifier" required value={form.identifier} onChange={(e) => set('identifier', e.target.value.trim())} className="font-mono" />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="santa-rule-type">{t('santa.ruleType')}</Label>
            <select id="santa-rule-type" className={SELECT} value={form.rule_type} onChange={(e) => set('rule_type', e.target.value as SantaRuleInput['rule_type'])}>
              {SANTA_RULE_TYPES.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <div>
            <Label htmlFor="santa-policy">{t('santa.policy')}</Label>
            <select id="santa-policy" className={SELECT} value={form.policy} onChange={(e) => {
              const policy = e.target.value as SantaRuleInput['policy'];
              setForm((f) => ({ ...f, policy, cel_expr: policy === 'CEL' ? f.cel_expr : '' }));
            }}>
              {SANTA_POLICIES.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <div>
            <Label htmlFor="santa-scope">{t('santa.scope')}</Label>
            <select id="santa-scope" className={SELECT} value={form.scope} onChange={(e) => {
              const scope = e.target.value as SantaRuleInput['scope'];
              setForm((f) => ({ ...f, scope, scope_value: scope === 'env' ? '' : f.scope_value }));
            }}>
              {SANTA_SCOPES.map((v) => <option key={v} value={v}>{t(`santa.scopes.${v}`)}</option>)}
            </select>
          </div>
          {form.scope !== 'env' && (
            <div>
              <Label htmlFor="santa-scope-value" required>{t('santa.scopeValue')}</Label>
              <Input id="santa-scope-value" required value={form.scope_value} onChange={(e) => set('scope_value', e.target.value.trim())} />
            </div>
          )}
        </div>
        {form.policy === 'CEL' && (
          <div>
            <Label htmlFor="santa-cel" required>CEL</Label>
            <textarea
              id="santa-cel"
              required
              rows={3}
              value={form.cel_expr}
              onChange={(e) => set('cel_expr', e.target.value)}
              className="w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] p-2 font-mono text-sm text-[color:var(--text-1)]"
            />
          </div>
        )}
        <div>
          <Label htmlFor="santa-msg">{t('santa.customMsg')}</Label>
          <Input id="santa-msg" value={form.custom_msg} onChange={(e) => set('custom_msg', e.target.value)} />
        </div>
        <div>
          <Label htmlFor="santa-url">{t('santa.customUrl')}</Label>
          <Input id="santa-url" type="url" value={form.custom_url} onChange={(e) => set('custom_url', e.target.value)} />
        </div>
        {message && <p role="alert" className="text-sm text-[color:var(--danger)]">{message}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
          <Button type="submit" disabled={save.isPending}>{t('common.save')}</Button>
        </div>
      </form>
    </ModalShell>
  );
}
