import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from '@tanstack/react-router';
import { ShieldCheck } from 'lucide-react';
import { usePageTitle } from '$/lib/usePageTitle';
import { StatusTabs } from '$/components/data/StatusTabs';
import { EventsTab } from './EventsTab';
import { MachinesTab } from './MachinesTab';
import { EMPTY_RULE, RuleFormModal, RulesTab, type RuleDraft } from './RulesTab';
import { SettingsTab } from './SettingsTab';

type Tab = 'rules' | 'events' | 'machines' | 'settings';

export function SantaPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.santa'));
  const { env } = useParams({ from: '/_app/env/$env/santa' });
  const [tab, setTab] = useState<Tab>('rules');
  // One rule form for every entry point: "Add rule", Edit, and the Allow/Block shortcuts on events.
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const closeDraft = useCallback(() => setDraft(null), []);

  const tabs: { value: Tab; label: string }[] = [
    { value: 'rules', label: t('santa.tabRules') },
    { value: 'events', label: t('santa.tabEvents') },
    { value: 'machines', label: t('santa.tabMachines') },
    { value: 'settings', label: t('santa.tabSettings') },
  ];

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 sm:px-6">
      <header>
        <h1 className="flex items-center gap-2 font-display text-xl font-semibold text-[color:var(--text-1)]">
          <ShieldCheck className="h-5 w-5 text-[color:var(--text-3)]" aria-hidden="true" />
          Santa
        </h1>
        <p className="mt-1 text-sm text-[color:var(--text-3)]">{t('santa.description')}</p>
      </header>

      <StatusTabs tabs={tabs} value={tab} onChange={setTab} />

      {tab === 'rules' && <RulesTab env={env} onAdd={() => setDraft(EMPTY_RULE)} onEdit={setDraft} />}
      {tab === 'events' && <EventsTab env={env} onRule={setDraft} />}
      {tab === 'machines' && <MachinesTab env={env} />}
      {tab === 'settings' && <SettingsTab env={env} />}

      {draft && <RuleFormModal env={env} initial={draft} onClose={closeDraft} />}
    </div>
  );
}
