/**
 * /dev/components — DEV-only component gallery.
 *
 * Lists every primitive / atom / data component with sensible default props
 * so design and a11y can be sanity-checked in dark + light + density modes
 * without running every feature page. Gated by import.meta.env.DEV at the
 * route level — never reachable in production builds.
 */
import { Button } from '$/components/atoms/Button';
import { Logo } from '$/components/atoms/Logo';
import { Skeleton, SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { StatCard } from '$/components/data/StatCard';
import { Sparkline } from '$/components/data/Sparkline';
import { StatusBadge } from '$/components/data/StatusBadge';
import { StatusPip } from '$/components/data/StatusPip';
import { StatusTabs } from '$/components/data/StatusTabs';
import { Pagination } from '$/components/data/Pagination';
import { SearchInput } from '$/components/data/SearchInput';
import { SortableHeader } from '$/components/data/SortableHeader';
import { DiffView } from '$/components/forms/DiffView';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { useState } from 'react';
import type { SortDir } from '$/api/types';

type DemoTab = 'all' | 'active' | 'inactive';
type DemoSort = 'name' | 'created';

export function ComponentGallery() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(2);
  const [code, setCode] = useState('SELECT name, version FROM osquery_info;');
  const [tab, setTab] = useState<DemoTab>('all');
  const [sort, setSort] = useState<DemoSort>('name');
  const [dir, setDir] = useState<SortDir>('asc');

  return (
    <div className="p-6 space-y-8 max-w-5xl mx-auto">
      <header>
        <h1 className="font-display text-2xl font-bold text-[color:var(--text-1)]">
          Component gallery
        </h1>
        <p className="text-sm text-[color:var(--text-3)] mt-1">
          DEV-only. Every primitive renders here so dark/light/density can be
          QA'd without spinning up the full app.
        </p>
      </header>

      <Section title="Buttons">
        <div className="flex flex-wrap gap-3">
          <Button>Primary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button disabled>Disabled</Button>
          <Button size="sm">Small</Button>
          <Button size="lg">Large</Button>
        </div>
      </Section>

      <Section title="Logo">
        <div className="flex items-end gap-6">
          <Logo size={24} decorative />
          <Logo size={48} decorative />
          <Logo size={72} decorative />
        </div>
      </Section>

      <Section title="Skeletons">
        <div className="space-y-2">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
        </div>
        <table className="w-full mt-3 border border-[color:var(--border)]">
          <tbody>
            <SkeletonRow cells={4} />
            <SkeletonRow cells={4} />
          </tbody>
        </table>
      </Section>

      <Section title="Empty state">
        <EmptyState
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="3" width="18" height="18" rx="2" />
            </svg>
          }
          title="Nothing to show yet."
          action={<Button size="sm">Create one</Button>}
        />
      </Section>

      <Section title="Stat cards + sparkline">
        <div className="grid grid-cols-3 gap-3">
          <StatCard
            label="Active nodes"
            value={1247}
            halo="success"
            trend="up"
            trendValue="+12"
            sparkline={[5, 8, 4, 9, 11, 14, 9, 12, 16, 19]}
          />
          <StatCard label="Inactive" value={38} halo="warning" />
          <StatCard label="Errors" value={0} halo="danger" />
        </div>
        <div className="mt-3">
          <Sparkline points={[5, 8, 4, 9, 11, 14, 9, 12, 16, 19]} width={240} height={48} />
        </div>
      </Section>

      <Section title="Status badges + pips">
        <div className="flex flex-wrap gap-4 items-center">
          <StatusBadge variant="success" label="Active" />
          <StatusBadge variant="warning" label="Degraded" />
          <StatusBadge variant="danger" label="Offline" />
          <StatusBadge variant="info" label="Pending" />
          <StatusBadge variant="signal" label="Live" live />
          <StatusPip variant="success" />
          <StatusPip variant="warning" />
          <StatusPip variant="danger" />
        </div>
      </Section>

      <Section title="Status tabs">
        <StatusTabs
          value={tab}
          onChange={(v) => setTab(v)}
          tabs={[
            { value: 'all' as const, label: 'All' },
            { value: 'active' as const, label: 'Active' },
            { value: 'inactive' as const, label: 'Inactive' },
          ]}
        />
      </Section>

      <Section title="Pagination">
        <Pagination
          page={page}
          pageSize={50}
          totalItems={213}
          totalPages={5}
          onPageChange={setPage}
        />
      </Section>

      <Section title="Search input">
        <SearchInput value={search} onChange={setSearch} placeholder="Search anything…" />
      </Section>

      <Section title="Sortable header">
        <table className="w-full">
          <thead>
            <tr>
              <SortableHeader<DemoSort>
                column="name"
                label="Name"
                currentSort={sort}
                currentDir={dir}
                onSortChange={(c, d) => {
                  setSort(c);
                  setDir(d);
                }}
              />
              <SortableHeader<DemoSort>
                column="created"
                label="Created"
                currentSort={sort}
                currentDir={dir}
                onSortChange={(c, d) => {
                  setSort(c);
                  setDir(d);
                }}
              />
            </tr>
          </thead>
        </table>
      </Section>

      <Section title="Diff view">
        <DiffView before={'a\nb\nc'} after={'a\nB\nc\nd'} />
      </Section>

      <Section title="Code editor (Monaco)">
        <CodeEditor
          value={code}
          onChange={setCode}
          language="sql"
          aria-label="Demo editor"
          height="180px"
        />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border border-[color:var(--border)] rounded-md p-4 bg-[color:var(--bg-1)]">
      <h2 className="font-display text-sm font-semibold uppercase tracking-wider text-[color:var(--text-3)] mb-3">
        {title}
      </h2>
      {children}
    </section>
  );
}

export default ComponentGallery;
