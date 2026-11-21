import { useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { ShieldCheck } from 'lucide-react';
import { getSantaAccess, santaQueryKey } from '$/api/santa';
import { EmptyState } from '$/components/data/EmptyState';
import { usePageTitle } from '$/lib/usePageTitle';
import { StatusTabs } from '$/components/data/StatusTabs';
import { BinaryModal } from './BinaryModal';
import { ChangesTab } from './ChangesTab';
import { EventsTab } from './EventsTab';
import { FileAccessTab } from './FileAccessTab';
import { MachinesTab } from './MachinesTab';
import { ReportsTab } from './ReportsTab';
import { RequestsTab } from './RequestsTab';
import { EMPTY_RULE, RuleFormModal, RulesTab, type RuleDraft } from './RulesTab';
import { SettingsTab } from './SettingsTab';

export const SANTA_TABS = ['rules', 'events', 'file-access', 'requests', 'changes', 'reports', 'machines', 'settings'] as const;
export type SantaTab = (typeof SANTA_TABS)[number];
type Tab = SantaTab;

export function SantaPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.santa'));
  const { env } = useParams({ from: '/_app/env/$env/santa' });
  // The tab and the open binary live in the URL, so both can be linked to.
  const search = useSearch({ from: '/_app/env/$env/santa' });
  const navigate = useNavigate({ from: '/_app/env/$env/santa' });
  const tab = search.tab ?? 'rules';
  const setTab = useCallback((next: Tab) => void navigate({ search: (s) => ({ ...s, tab: next }) }), [navigate]);
  const openBinary = useCallback((sha256: string) => void navigate({ search: (s) => ({ ...s, binary: sha256 }) }), [navigate]);
  const closeBinary = useCallback(() => void navigate({ search: (s) => ({ ...s, binary: undefined }) }), [navigate]);
  // One rule form for every entry point: "Add rule", Edit, and the Allow/Block shortcuts on events.
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const closeDraft = useCallback(() => setDraft(null), []);
  const access = useQuery({ queryKey: santaQueryKey(env, 'access'), queryFn: () => getSantaAccess(env) });
  const admin = access.data?.admin ?? false;

  const tabs: { value: Tab; label: string }[] = [
    { value: 'rules', label: t('santa.tabRules') },
    { value: 'events', label: t('santa.tabEvents') },
    { value: 'file-access', label: t('santa.tabFileAccess') },
    { value: 'requests', label: t('santa.tabRequests') },
    { value: 'changes', label: t('santa.changes.tab') },
    { value: 'reports', label: t('santa.tabReports') },
    { value: 'machines', label: t('santa.tabMachines') },
    { value: 'settings', label: t('santa.tabSettings') },
  ];
  // Approvers who are not environment admins see the approval queue only.
  const shown = admin ? tabs : tabs.filter((x) => x.value === 'requests');
  const current = admin ? tab : 'requests';
  const denied = access.isError || (access.data && !access.data.admin && !access.data.approver);

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 sm:px-6">
      <header>
        <h1 className="flex items-center gap-2 font-display text-xl font-semibold text-[color:var(--text-1)]">
          <ShieldCheck className="h-5 w-5 text-[color:var(--text-3)]" aria-hidden="true" />
          Santa
        </h1>
        <p className="mt-1 text-sm text-[color:var(--text-3)]">{t('santa.description')}</p>
      </header>

      {denied ? (
        <EmptyState icon={<ShieldCheck />} title={t('santa.approvers.noAccess')} />
      ) : access.data && (
        <>
          <StatusTabs tabs={shown} value={current} onChange={setTab} />
          {current === 'requests' && <RequestsTab env={env} admin={admin} onBinary={openBinary} />}
        </>
      )}

      {admin && tab === 'rules' && <RulesTab env={env} onAdd={() => setDraft(EMPTY_RULE)} onEdit={setDraft} />}
      {admin && tab === 'events' && <EventsTab env={env} onRule={setDraft} onBinary={openBinary} />}
      {admin && tab === 'file-access' && <FileAccessTab env={env} />}
      {admin && tab === 'changes' && <ChangesTab env={env} />}
      {admin && tab === 'reports' && <ReportsTab env={env} onBinary={openBinary} />}
      {admin && tab === 'machines' && <MachinesTab env={env} />}
      {admin && tab === 'settings' && <SettingsTab env={env} />}

      {draft && <RuleFormModal env={env} initial={draft} onClose={closeDraft} />}
      {admin && search.binary && <BinaryModal env={env} sha256={search.binary} onClose={closeBinary} />}
    </div>
  );
}
