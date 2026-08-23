import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { OsqueryTable } from '$/api/types';
import { NoCodeQueryBuilder, type QueryBuilderSummary } from './NoCodeQueryBuilder';

const mockGetOsqueryTables = vi.fn<() => Promise<OsqueryTable[]>>();

vi.mock('$/api/osquery', () => ({
  getOsqueryTables: () => mockGetOsqueryTables(),
}));

const tables: OsqueryTable[] = [
  {
    name: 'processes',
    description: 'Running processes',
    url: 'https://osquery.io/schema/#processes',
    platforms: ['darwin', 'linux', 'windows'],
    filter: '',
    columns: [
      { name: 'pid', type: 'bigint', description: 'Process identifier' },
      { name: 'name', type: 'text', description: 'Process name' },
      { name: 'path', type: 'text', description: 'Executable path' },
    ],
  },
];

function renderBuilder({
  onSqlChange = vi.fn<(sql: string) => void>(),
  draftKey,
  onSummaryChange,
}: {
  onSqlChange?: (sql: string) => void;
  draftKey?: string;
  onSummaryChange?: (summary: QueryBuilderSummary) => void;
} = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <NoCodeQueryBuilder
        onSqlChange={onSqlChange}
        onEditSql={vi.fn()}
        draftKey={draftKey}
        onSummaryChange={onSummaryChange}
      />
    </QueryClientProvider>,
  );
  return { ...view, onSqlChange };
}

describe('NoCodeQueryBuilder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.sessionStorage.clear();
    mockGetOsqueryTables.mockResolvedValue(tables);
  });

  it('builds an inline filter token from the searchable field picker', async () => {
    const user = userEvent.setup();
    const { onSqlChange } = renderBuilder();

    await user.click(await screen.findByRole('button', { name: 'Add filter' }));
    await user.click(await screen.findByText('name', { selector: 'span' }));
    expect(screen.getByRole('textbox', { name: 'Filter 1 value' })).toHaveFocus();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter 1 operator' }), 'contains');
    await user.type(screen.getByRole('textbox', { name: 'Filter 1 value' }), 'ssh');

    await waitFor(() => {
      expect(onSqlChange).toHaveBeenLastCalledWith([
        'SELECT *',
        'FROM processes',
        "WHERE name LIKE '%ssh%'",
        'LIMIT 100;',
      ].join('\n'));
    });
    expect(screen.getByText('Where')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument();
  });

  it('treats All columns as a mode and starts a specific selection with one click', async () => {
    const user = userEvent.setup();
    const { onSqlChange } = renderBuilder();

    await user.click(await screen.findByRole('button', { name: 'Choose result columns, currently All columns' }));
    const nameColumn = screen.getByRole('button', { name: /name.*text.*Process name/i });
    expect(nameColumn).toHaveAttribute('aria-pressed', 'false');
    await user.click(nameColumn);

    await waitFor(() => {
      expect(onSqlChange).toHaveBeenLastCalledWith('SELECT name\nFROM processes\nLIMIT 100;');
    });
    expect(screen.getByRole('button', { name: 'Choose result columns, currently name' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'All columns' }));
    await waitFor(() => {
      expect(onSqlChange).toHaveBeenLastCalledWith('SELECT *\nFROM processes\nLIMIT 100;');
    });
  });

  it('clears filters without resetting result settings', async () => {
    const user = userEvent.setup();
    const { onSqlChange } = renderBuilder();

    await user.click(await screen.findByRole('button', { name: 'Add filter' }));
    await user.click(await screen.findByText('pid', { selector: 'span' }));
    await user.type(screen.getByRole('spinbutton', { name: 'Filter 1 value' }), '42');
    await user.clear(screen.getByRole('spinbutton', { name: 'Row limit' }));
    await user.type(screen.getByRole('spinbutton', { name: 'Row limit' }), '25');
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));

    expect(screen.queryByRole('combobox', { name: 'Filter 1 column' })).not.toBeInTheDocument();
    expect(screen.getByRole('spinbutton', { name: 'Row limit' })).toHaveValue(25);
    await waitFor(() => {
      expect(onSqlChange).toHaveBeenLastCalledWith('SELECT *\nFROM processes\nLIMIT 25;');
    });
  });

  it('keeps sorting secondary and supports undo after a full reset', async () => {
    const user = userEvent.setup();
    const { onSqlChange } = renderBuilder();

    expect(await screen.findByRole('button', { name: 'Add sorting' })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Sort results by column' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add sorting' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Sort results by column' }), 'name');
    await user.clear(screen.getByRole('spinbutton', { name: 'Row limit' }));
    await user.type(screen.getByRole('spinbutton', { name: 'Row limit' }), '25');
    await user.click(screen.getByRole('button', { name: 'Reset query' }));

    expect(screen.getByRole('spinbutton', { name: 'Row limit' })).toHaveValue(100);
    expect(screen.queryByRole('combobox', { name: 'Sort results by column' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Undo' }));
    expect(screen.getByRole('spinbutton', { name: 'Row limit' })).toHaveValue(25);
    expect(screen.getByRole('combobox', { name: 'Sort results by column' })).toHaveValue('name');
    await waitFor(() => {
      expect(onSqlChange).toHaveBeenLastCalledWith('SELECT *\nFROM processes\nORDER BY name ASC\nLIMIT 25;');
    });
  });

  it('restores an environment-scoped draft from session storage', async () => {
    const user = userEvent.setup();
    const first = renderBuilder({ draftKey: 'query-builder:test-env' });

    await user.click(await screen.findByRole('button', { name: 'Choose result columns, currently All columns' }));
    await user.click(screen.getByRole('button', { name: /name.*text.*Process name/i }));
    await user.clear(screen.getByRole('spinbutton', { name: 'Row limit' }));
    await user.type(screen.getByRole('spinbutton', { name: 'Row limit' }), '25');
    await waitFor(() => {
      expect(window.sessionStorage.getItem('query-builder:test-env')).toContain('"limit":25');
    });
    first.unmount();

    const restoredSql = vi.fn<(sql: string) => void>();
    renderBuilder({ onSqlChange: restoredSql, draftKey: 'query-builder:test-env' });
    expect(await screen.findByRole('button', { name: 'Choose result columns, currently name' })).toBeInTheDocument();
    expect(screen.getByRole('spinbutton', { name: 'Row limit' })).toHaveValue(25);
    await waitFor(() => {
      expect(restoredSql).toHaveBeenLastCalledWith('SELECT name\nFROM processes\nLIMIT 25;');
    });
  });
});
