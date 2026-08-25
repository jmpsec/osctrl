import * as Popover from '@radix-ui/react-popover';
import { useEffect, useMemo, useRef, useState, type ComponentPropsWithoutRef, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowUpDown,
  Braces,
  Check,
  ChevronDown,
  Columns3,
  Hash,
  Plus,
  Search,
  Table2,
  TextCursorInput,
  Undo2,
  X,
} from 'lucide-react';
import { getOsqueryTables } from '$/api/osquery';
import type { OsqueryTable, OsqueryTableColumn } from '$/api/types';
import { cn } from '$/lib/cn';
import {
  buildOsquerySql,
  QUERY_BUILDER_OPERATORS,
  type QueryBuilderCondition,
  type QueryBuilderOperator,
  type QueryBuilderState,
} from '../query-builder';

interface NoCodeQueryBuilderProps {
  onSqlChange: (sql: string) => void;
  onEditSql: () => void;
  draftKey?: string;
  onSummaryChange?: (summary: QueryBuilderSummary) => void;
}

export interface QueryBuilderSummary {
  columnLabel: string;
  filterCount: number;
  limit: number;
}

interface QueryBuilderRecents {
  tables: string[];
  columns: Record<string, string[]>;
}

const DEFAULT_TABLE = 'osquery_info';
const DEFAULT_LIMIT = 100;
const MAX_RECENTS = 4;
const COMMON_TABLE_NAMES = ['processes', 'users', 'listening_ports', 'system_info', 'osquery_info'];
const COMMON_COLUMN_NAMES = ['name', 'pid', 'path', 'version', 'platform', 'username', 'address', 'port'];

const DEFAULT_BUILDER_STATE: QueryBuilderState = {
  table: DEFAULT_TABLE,
  columns: [],
  conditions: [],
  orderBy: '',
  orderDirection: 'ASC',
  limit: DEFAULT_LIMIT,
};

const focusClass = 'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]';
const fieldClass = cn(
  'h-8 rounded-md bg-[color:var(--bg-1)] px-2.5 text-base text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)] sm:text-sm',
  'focus:outline focus:outline-2 -outline-offset-1 focus:outline-[color:var(--signal)]',
);

function platformLabel(platforms: string[]) {
  if (platforms.length === 0 || platforms.length >= 3) return 'All platforms';
  return platforms.map((platform) => platform === 'darwin' ? 'macOS' : platform).join(' · ');
}

function isNumericType(type: string | undefined) {
  return Boolean(type && /^(?:bigint|double|float|int|integer|smallint|unsigned_bigint)$/i.test(type));
}

function defaultOperatorForColumn(_column: OsqueryTableColumn): QueryBuilderOperator {
  // Equality is deliberately conservative for fleet-wide operational queries.
  // The available choices below still adapt to the selected column's type.
  return 'equals';
}

function operatorsForColumn(column: OsqueryTableColumn | undefined) {
  if (!column || !isNumericType(column.type)) return QUERY_BUILDER_OPERATORS;
  return QUERY_BUILDER_OPERATORS.filter((operator) => (
    operator.value !== 'contains' && operator.value !== 'starts_with'
  ));
}

function suggestionsForColumn(column: OsqueryTableColumn | undefined) {
  if (column?.name.toLowerCase() === 'platform') return ['darwin', 'linux', 'windows'];
  if (column && /^(?:active|disabled|enabled|hidden|is_|has_)/i.test(column.name)) return ['1', '0'];
  return [];
}

function isQueryBuilderState(value: unknown): value is QueryBuilderState {
  if (!value || typeof value !== 'object') return false;
  const state = value as Partial<QueryBuilderState>;
  return (
    typeof state.table === 'string'
    && Array.isArray(state.columns)
    && state.columns.every((column) => typeof column === 'string')
    && Array.isArray(state.conditions)
    && state.conditions.every((condition) => (
      condition
      && typeof condition.id === 'number'
      && typeof condition.column === 'string'
      && typeof condition.operator === 'string'
      && typeof condition.value === 'string'
    ))
    && typeof state.orderBy === 'string'
    && (state.orderDirection === 'ASC' || state.orderDirection === 'DESC')
    && typeof state.limit === 'number'
  );
}

function readDraft(draftKey: string | undefined): QueryBuilderState {
  if (!draftKey || typeof window === 'undefined') return DEFAULT_BUILDER_STATE;
  try {
    const stored = window.sessionStorage.getItem(draftKey);
    if (!stored) return DEFAULT_BUILDER_STATE;
    const parsed: unknown = JSON.parse(stored);
    return isQueryBuilderState(parsed) ? parsed : DEFAULT_BUILDER_STATE;
  } catch {
    return DEFAULT_BUILDER_STATE;
  }
}

function readRecents(draftKey: string | undefined): QueryBuilderRecents {
  if (!draftKey || typeof window === 'undefined') return { tables: [], columns: {} };
  try {
    const stored = window.sessionStorage.getItem(`${draftKey}:recents`);
    if (!stored) return { tables: [], columns: {} };
    const parsed = JSON.parse(stored) as Partial<QueryBuilderRecents>;
    return {
      tables: Array.isArray(parsed.tables) ? parsed.tables.filter((item): item is string => typeof item === 'string') : [],
      columns: parsed.columns && typeof parsed.columns === 'object' ? parsed.columns : {},
    };
  } catch {
    return { tables: [], columns: {} };
  }
}

function addRecent(items: string[], value: string) {
  return [value, ...items.filter((item) => item !== value)].slice(0, MAX_RECENTS);
}

function ColumnTypeIcon({ type }: { type: string | undefined }) {
  if (isNumericType(type)) {
    return <Hash size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />;
  }
  if (type?.toLowerCase() === 'text') {
    return <TextCursorInput size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />;
  }
  return <Braces size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />;
}

function PickerSurface({
  children,
  className,
  onCloseAutoFocus,
}: {
  children: ReactNode;
  className?: string;
  onCloseAutoFocus?: ComponentPropsWithoutRef<typeof Popover.Content>['onCloseAutoFocus'];
}) {
  return (
    <Popover.Portal>
      <Popover.Content
        align="start"
        sideOffset={6}
        collisionPadding={16}
        onCloseAutoFocus={onCloseAutoFocus}
        className={cn(
          'z-50 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg bg-[color:var(--bg-1)]',
          'shadow-[0_12px_36px_rgba(0,0,0,0.16)] ring-1 ring-black/10 dark:shadow-none dark:ring-white/10',
          className,
        )}
      >
        {children}
      </Popover.Content>
    </Popover.Portal>
  );
}

function PickerSearch({
  id,
  name,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  name: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <div className="relative border-b border-[color:var(--border)] p-2">
      <label htmlFor={id} className="sr-only">{placeholder}</label>
      <Search
        size={16}
        strokeWidth={1.8}
        aria-hidden
        className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-[color:var(--text-3)]"
      />
      <input
        id={id}
        name={name}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className={cn(fieldClass, 'w-full pl-9')}
      />
    </div>
  );
}

function CompactSelect({
  value,
  onChange,
  name,
  ariaLabel,
  children,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  name: string;
  ariaLabel: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('inline-grid h-8 min-w-0 grid-cols-[1fr_2rem]', className)}>
      <select
        name={name}
        aria-label={ariaLabel}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="col-span-full row-start-1 min-w-0 appearance-none bg-transparent pl-2 pr-8 text-base text-[color:var(--text-1)] outline-none sm:text-sm"
      >
        {children}
      </select>
      <ChevronDown
        size={16}
        strokeWidth={1.8}
        aria-hidden
        className="pointer-events-none col-start-2 row-start-1 place-self-center text-[color:var(--text-3)]"
      />
    </div>
  );
}

function PickerGroupLabel({ children }: { children: ReactNode }) {
  return (
    <div className="px-3 pb-1 pt-2 text-sm font-medium text-[color:var(--text-3)]">
      {children}
    </div>
  );
}

function TablePickerOption({
  table,
  active,
  onSelect,
}: {
  table: OsqueryTable;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'flex w-full min-w-0 items-start gap-2 rounded-md p-2 text-left text-sm',
        active ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]' : 'text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)]',
        focusClass,
      )}
    >
      <Table2 size={16} strokeWidth={1.8} aria-hidden className="mt-0.5 shrink-0 text-[color:var(--text-3)]" />
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 items-center gap-2 font-medium">
          <span className="truncate">{table.name}</span>
          <span className="shrink-0 font-normal text-[color:var(--text-3)]">{platformLabel(table.platforms)}</span>
        </span>
        {table.description && <span className="mt-0.5 block truncate text-[color:var(--text-3)]">{table.description}</span>}
      </span>
      {active && <Check size={16} strokeWidth={2} aria-hidden className="mt-0.5 shrink-0 text-[color:var(--signal)]" />}
    </button>
  );
}

function ColumnPickerOption({
  column,
  checked,
  onSelect,
}: {
  column: OsqueryTableColumn;
  checked: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn('flex w-full min-w-0 items-start gap-2 rounded-md p-2 text-left text-sm hover:bg-[color:var(--bg-3)]', focusClass)}
      aria-pressed={checked}
    >
      <span className={cn(
        'mt-0.5 inline-flex size-4 shrink-0 items-center justify-center rounded-sm ring-1 ring-inset',
        checked ? 'bg-[color:var(--signal)] text-white ring-[color:var(--signal)]' : 'ring-[color:var(--border-strong)]',
      )}>
        {checked && <Check size={14} strokeWidth={2.2} aria-hidden />}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2 font-medium text-[color:var(--text-1)]">
          <ColumnTypeIcon type={column.type} />
          <span className="truncate">{column.name}</span>
        </span>
        <span className="mt-0.5 block truncate text-[color:var(--text-3)]">{column.type}{column.description ? ` · ${column.description}` : ''}</span>
      </span>
    </button>
  );
}

function FilterFieldOption({
  column,
  onSelect,
}: {
  column: OsqueryTableColumn;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'flex w-full min-w-0 items-start gap-2 rounded-md p-2 text-left text-sm text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
        focusClass,
      )}
    >
      <ColumnTypeIcon type={column.type} />
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium">{column.name}</span>
        <span className="mt-0.5 block truncate text-[color:var(--text-3)]">{column.type}{column.description ? ` · ${column.description}` : ''}</span>
      </span>
    </button>
  );
}

export function NoCodeQueryBuilder({
  onSqlChange,
  onEditSql,
  draftKey,
  onSummaryChange,
}: NoCodeQueryBuilderProps) {
  const { data: tables = [], isLoading, isError } = useQuery({
    queryKey: ['osquery-tables'],
    queryFn: getOsqueryTables,
    staleTime: Infinity,
    retry: 1,
  });
  const [initialDraft] = useState(() => readDraft(draftKey));
  const [tableName, setTableName] = useState(initialDraft.table);
  const [tableSearch, setTableSearch] = useState('');
  const [columnSearch, setColumnSearch] = useState('');
  const [filterSearch, setFilterSearch] = useState('');
  const [tablePickerOpen, setTablePickerOpen] = useState(false);
  const [columnPickerOpen, setColumnPickerOpen] = useState(false);
  const [filterPickerOpen, setFilterPickerOpen] = useState(false);
  const [columns, setColumns] = useState<string[]>(initialDraft.columns);
  const [conditions, setConditions] = useState<QueryBuilderCondition[]>(initialDraft.conditions);
  const [orderBy, setOrderBy] = useState(initialDraft.orderBy);
  const [orderDirection, setOrderDirection] = useState<'ASC' | 'DESC'>(initialDraft.orderDirection);
  const [limit, setLimit] = useState(initialDraft.limit);
  const [sortOpen, setSortOpen] = useState(Boolean(initialDraft.orderBy));
  const [resetSnapshot, setResetSnapshot] = useState<QueryBuilderState | null>(null);
  const [recents, setRecents] = useState<QueryBuilderRecents>(() => readRecents(draftKey));
  const nextConditionId = useRef(Math.max(0, ...initialDraft.conditions.map((condition) => condition.id)) + 1);
  const valueInputRefs = useRef(new Map<number, HTMLInputElement>());
  const pendingValueFocusId = useRef<number | null>(null);
  const resetTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (tables.length === 0 || tables.some((table) => table.name === tableName)) return;
    setTableName(tables.find((table) => table.name === DEFAULT_TABLE)?.name ?? tables[0].name);
  }, [tableName, tables]);

  const selectedTable = useMemo(
    () => tables.find((table) => table.name === tableName),
    [tableName, tables],
  );
  const availableColumns = selectedTable?.columns ?? [];
  const visibleTables = useMemo(() => {
    const query = tableSearch.trim().toLowerCase();
    return [...tables]
      .filter((table) => !query || `${table.name} ${table.description ?? ''} ${table.platforms.join(' ')}`.toLowerCase().includes(query))
      .sort((left, right) => left.name.localeCompare(right.name));
  }, [tableSearch, tables]);
  const recentTables = useMemo(() => (
    tableSearch.trim() ? [] : recents.tables
      .map((name) => visibleTables.find((table) => table.name === name))
      .filter((table): table is OsqueryTable => Boolean(table))
  ), [recents.tables, tableSearch, visibleTables]);
  const commonTables = useMemo(() => {
    if (tableSearch.trim()) return [];
    const recentNames = new Set(recentTables.map((table) => table.name));
    return COMMON_TABLE_NAMES
      .map((name) => visibleTables.find((table) => table.name === name))
      .filter((table): table is OsqueryTable => table !== undefined && !recentNames.has(table.name));
  }, [recentTables, tableSearch, visibleTables]);
  const remainingTables = useMemo(() => {
    const priorityNames = new Set([...recentTables, ...commonTables].map((table) => table.name));
    return visibleTables.filter((table) => !priorityNames.has(table.name));
  }, [commonTables, recentTables, visibleTables]);
  const visibleColumns = useMemo(() => {
    const query = columnSearch.trim().toLowerCase();
    return availableColumns.filter((column) => (
      !query || `${column.name} ${column.type} ${column.description ?? ''}`.toLowerCase().includes(query)
    ));
  }, [availableColumns, columnSearch]);
  const recentColumns = useMemo(() => (
    columnSearch.trim() ? [] : (recents.columns[tableName] ?? [])
      .map((name) => visibleColumns.find((column) => column.name === name))
      .filter((column): column is OsqueryTableColumn => Boolean(column))
  ), [columnSearch, recents.columns, tableName, visibleColumns]);
  const commonColumns = useMemo(() => {
    if (columnSearch.trim()) return [];
    const recentNames = new Set(recentColumns.map((column) => column.name));
    return COMMON_COLUMN_NAMES
      .map((name) => visibleColumns.find((column) => column.name === name))
      .filter((column): column is OsqueryTableColumn => column !== undefined && !recentNames.has(column.name));
  }, [columnSearch, recentColumns, visibleColumns]);
  const remainingColumns = useMemo(() => {
    const priorityNames = new Set([...recentColumns, ...commonColumns].map((column) => column.name));
    return visibleColumns.filter((column) => !priorityNames.has(column.name));
  }, [commonColumns, recentColumns, visibleColumns]);
  const visibleFilterColumns = useMemo(() => {
    const query = filterSearch.trim().toLowerCase();
    return availableColumns.filter((column) => (
      !query || `${column.name} ${column.type} ${column.description ?? ''}`.toLowerCase().includes(query)
    ));
  }, [availableColumns, filterSearch]);
  const recentFilterColumns = useMemo(() => (
    filterSearch.trim() ? [] : (recents.columns[tableName] ?? [])
      .map((name) => visibleFilterColumns.find((column) => column.name === name))
      .filter((column): column is OsqueryTableColumn => Boolean(column))
  ), [filterSearch, recents.columns, tableName, visibleFilterColumns]);
  const commonFilterColumns = useMemo(() => {
    if (filterSearch.trim()) return [];
    const recentNames = new Set(recentFilterColumns.map((column) => column.name));
    return COMMON_COLUMN_NAMES
      .map((name) => visibleFilterColumns.find((column) => column.name === name))
      .filter((column): column is OsqueryTableColumn => column !== undefined && !recentNames.has(column.name));
  }, [filterSearch, recentFilterColumns, visibleFilterColumns]);
  const remainingFilterColumns = useMemo(() => {
    const priorityNames = new Set([...recentFilterColumns, ...commonFilterColumns].map((column) => column.name));
    return visibleFilterColumns.filter((column) => !priorityNames.has(column.name));
  }, [commonFilterColumns, recentFilterColumns, visibleFilterColumns]);

  const builderState: QueryBuilderState = useMemo(() => ({
    table: tableName,
    columns,
    conditions,
    orderBy,
    orderDirection,
    limit,
  }), [columns, conditions, limit, orderBy, orderDirection, tableName]);
  const sql = useMemo(
    () => buildOsquerySql(builderState, selectedTable),
    [builderState, selectedTable],
  );

  const allColumnsSelected = columns.length === 0;
  const columnLabel = allColumnsSelected
    ? 'All columns'
    : columns.length === 1
      ? columns[0]
      : `${columns.length} columns`;
  const hasCustomQuery = conditions.length > 0 || !allColumnsSelected || orderBy !== '' || limit !== DEFAULT_LIMIT;

  useEffect(() => {
    onSqlChange(sql);
  }, [onSqlChange, sql]);

  useEffect(() => {
    onSummaryChange?.({ columnLabel, filterCount: conditions.length, limit });
  }, [columnLabel, conditions.length, limit, onSummaryChange]);

  useEffect(() => {
    if (!draftKey || typeof window === 'undefined') return;
    try {
      window.sessionStorage.setItem(draftKey, JSON.stringify(builderState));
    } catch {
      // A full or unavailable storage area should not block query composition.
    }
  }, [builderState, draftKey]);

  useEffect(() => {
    if (!draftKey || typeof window === 'undefined') return;
    try {
      window.sessionStorage.setItem(`${draftKey}:recents`, JSON.stringify(recents));
    } catch {
      // Recent shortcuts are opportunistic and can safely fail closed.
    }
  }, [draftKey, recents]);

  useEffect(() => () => {
    if (resetTimer.current !== undefined) window.clearTimeout(resetTimer.current);
  }, []);

  function chooseTable(table: OsqueryTable) {
    setTableName(table.name);
    setColumns([]);
    setConditions([]);
    setOrderBy('');
    setOrderDirection('ASC');
    setSortOpen(false);
    setRecents((current) => ({ ...current, tables: addRecent(current.tables, table.name) }));
    setTableSearch('');
    setTablePickerOpen(false);
  }

  function rememberColumn(columnName: string) {
    setRecents((current) => ({
      ...current,
      columns: {
        ...current.columns,
        [tableName]: addRecent(current.columns[tableName] ?? [], columnName),
      },
    }));
  }

  function toggleColumn(columnName: string) {
    const allNames = availableColumns.map((column) => column.name);
    setColumns((current) => {
      if (current.length === 0) return [columnName];
      const next = current.includes(columnName)
        ? current.filter((name) => name !== columnName)
        : [...current, columnName];
      return next.length === allNames.length ? [] : next;
    });
    rememberColumn(columnName);
  }

  function addCondition(column: OsqueryTableColumn) {
    const id = nextConditionId.current++;
    setConditions((current) => [
      ...current,
      {
        id,
        column: column.name,
        operator: defaultOperatorForColumn(column),
        value: '',
      },
    ]);
    rememberColumn(column.name);
    pendingValueFocusId.current = id;
    setFilterSearch('');
    setFilterPickerOpen(false);
  }

  function updateCondition(id: number, patch: Partial<QueryBuilderCondition>) {
    setConditions((current) => current.map((condition) => (
      condition.id === id ? { ...condition, ...patch } : condition
    )));
  }

  function changeConditionColumn(id: number, columnName: string) {
    const column = availableColumns.find((item) => item.name === columnName);
    if (!column) return;
    setConditions((current) => current.map((condition) => {
      if (condition.id !== id) return condition;
      const availableOperators = operatorsForColumn(column);
      const operator = availableOperators.some((item) => item.value === condition.operator)
        ? condition.operator
        : defaultOperatorForColumn(column);
      return { ...condition, column: columnName, operator };
    }));
    rememberColumn(columnName);
    window.setTimeout(() => valueInputRefs.current.get(id)?.focus(), 0);
  }

  function clearFilters() {
    setConditions([]);
    setFilterSearch('');
  }

  function resetQuery() {
    setResetSnapshot(builderState);
    setColumns([]);
    setConditions([]);
    setOrderBy('');
    setOrderDirection('ASC');
    setLimit(DEFAULT_LIMIT);
    setSortOpen(false);
    if (resetTimer.current !== undefined) window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => setResetSnapshot(null), 10_000);
  }

  function undoReset() {
    if (!resetSnapshot) return;
    setTableName(resetSnapshot.table);
    setColumns(resetSnapshot.columns);
    setConditions(resetSnapshot.conditions);
    setOrderBy(resetSnapshot.orderBy);
    setOrderDirection(resetSnapshot.orderDirection);
    setLimit(resetSnapshot.limit);
    setSortOpen(Boolean(resetSnapshot.orderBy));
    setResetSnapshot(null);
    if (resetTimer.current !== undefined) window.clearTimeout(resetTimer.current);
  }

  return (
    <div className="min-w-0">
      <section className="px-4 py-4 sm:px-5" aria-label="No-code query builder">
        {isLoading && (
          <div className="h-12 animate-pulse rounded-lg bg-[color:var(--bg-3)]" aria-label="Loading query builder" />
        )}
        {isError && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-[color:var(--danger)]/5 p-3 text-sm text-[color:var(--danger)] ring-1 ring-inset ring-[color:var(--danger)]/20">
            <p>The osquery schema could not be loaded. Use the SQL editor to continue.</p>
            <button type="button" onClick={onEditSql} className={cn('font-medium underline', focusClass)}>Edit SQL</button>
          </div>
        )}

        {!isLoading && !isError && (
          <div
            className="rounded-lg bg-[color:var(--bg-3)]/70 p-2 ring-1 ring-inset ring-[color:var(--border)]"
            aria-label="Query filters"
          >
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Popover.Root open={tablePickerOpen} onOpenChange={setTablePickerOpen}>
                <Popover.Trigger asChild>
                  <button
                    type="button"
                    className={cn(
                      'inline-flex h-8 max-w-full items-center gap-1.5 rounded-md bg-[color:var(--bg-1)] py-1.5 pr-2 pl-1.5 text-sm text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)] hover:bg-[color:var(--bg-3)]',
                      focusClass,
                    )}
                    aria-label={`Choose table, currently ${tableName}`}
                  >
                    <Table2 size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />
                    <span className="text-[color:var(--text-3)]">From</span>
                    <span className="min-w-0 truncate font-medium">{tableName}</span>
                    <ChevronDown size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />
                  </button>
                </Popover.Trigger>
                <PickerSurface>
                  <PickerSearch id="query-table-search" name="query-table-search" value={tableSearch} onChange={setTableSearch} placeholder="Search tables" />
                  <div className="max-h-80 overflow-y-auto p-1" role="list">
                    {recentTables.length > 0 && <PickerGroupLabel>Recent</PickerGroupLabel>}
                    {recentTables.map((table) => (
                      <TablePickerOption
                        key={`recent-${table.name}`}
                        table={table}
                        active={table.name === tableName}
                        onSelect={() => chooseTable(table)}
                      />
                    ))}
                    {commonTables.length > 0 && <PickerGroupLabel>Common</PickerGroupLabel>}
                    {commonTables.map((table) => (
                      <TablePickerOption
                        key={`common-${table.name}`}
                        table={table}
                        active={table.name === tableName}
                        onSelect={() => chooseTable(table)}
                      />
                    ))}
                    {(recentTables.length > 0 || commonTables.length > 0) && remainingTables.length > 0 && <PickerGroupLabel>All tables</PickerGroupLabel>}
                    {remainingTables.map((table) => (
                      <TablePickerOption
                        key={table.name}
                        table={table}
                        active={table.name === tableName}
                        onSelect={() => chooseTable(table)}
                      />
                    ))}
                    {visibleTables.length === 0 && <p className="p-3 text-sm text-[color:var(--text-3)]">No tables match that search.</p>}
                  </div>
                </PickerSurface>
              </Popover.Root>

              <Popover.Root open={columnPickerOpen} onOpenChange={setColumnPickerOpen}>
                <Popover.Trigger asChild>
                  <button
                    type="button"
                    className={cn(
                      'inline-flex h-8 max-w-full items-center gap-1.5 rounded-md bg-[color:var(--bg-1)] py-1.5 pr-2 pl-1.5 text-sm text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)] hover:bg-[color:var(--bg-3)]',
                      focusClass,
                    )}
                    aria-label={`Choose result columns, currently ${columnLabel}`}
                  >
                    <Columns3 size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />
                    <span className="text-[color:var(--text-3)]">Select</span>
                    <span className="min-w-0 truncate font-medium">{columnLabel}</span>
                    <ChevronDown size={16} strokeWidth={1.8} aria-hidden className="shrink-0 text-[color:var(--text-3)]" />
                  </button>
                </Popover.Trigger>
                <PickerSurface>
                  <PickerSearch id="query-column-search" name="query-column-search" value={columnSearch} onChange={setColumnSearch} placeholder="Search columns" />
                  <div className="border-b border-[color:var(--border)] p-1">
                    <button
                      type="button"
                      onClick={() => setColumns([])}
                      className={cn('flex w-full items-center gap-2 rounded-md p-2 text-left text-sm hover:bg-[color:var(--bg-3)]', focusClass)}
                      aria-pressed={allColumnsSelected}
                    >
                      <span className={cn(
                        'inline-flex size-4 shrink-0 items-center justify-center rounded-sm ring-1 ring-inset',
                        allColumnsSelected ? 'bg-[color:var(--signal)] text-white ring-[color:var(--signal)]' : 'ring-[color:var(--border-strong)]',
                      )}>
                        {allColumnsSelected && <Check size={14} strokeWidth={2.2} aria-hidden />}
                      </span>
                      <span className="font-medium text-[color:var(--text-1)]">All columns</span>
                    </button>
                  </div>
                  <div className="max-h-72 overflow-y-auto p-1" role="list">
                    {recentColumns.length > 0 && <PickerGroupLabel>Recent columns</PickerGroupLabel>}
                    {recentColumns.map((column) => (
                      <ColumnPickerOption
                        key={`recent-${column.name}`}
                        column={column}
                        checked={columns.includes(column.name)}
                        onSelect={() => toggleColumn(column.name)}
                      />
                    ))}
                    {commonColumns.length > 0 && <PickerGroupLabel>Common columns</PickerGroupLabel>}
                    {commonColumns.map((column) => (
                      <ColumnPickerOption
                        key={`common-${column.name}`}
                        column={column}
                        checked={columns.includes(column.name)}
                        onSelect={() => toggleColumn(column.name)}
                      />
                    ))}
                    {remainingColumns.length > 0 && <PickerGroupLabel>Choose specific columns</PickerGroupLabel>}
                    {remainingColumns.map((column) => (
                      <ColumnPickerOption
                        key={column.name}
                        column={column}
                        checked={columns.includes(column.name)}
                        onSelect={() => toggleColumn(column.name)}
                      />
                    ))}
                    {visibleColumns.length === 0 && <p className="p-3 text-sm text-[color:var(--text-3)]">No columns match that search.</p>}
                  </div>
                </PickerSurface>
              </Popover.Root>

            </div>

            {conditions.length > 0 && (
              <div className="mt-2 flex min-w-0 flex-col items-start gap-2">

              {conditions.map((condition, index) => {
                const operator = QUERY_BUILDER_OPERATORS.find((item) => item.value === condition.operator);
                const column = availableColumns.find((item) => item.name === condition.column);
                const availableOperators = operatorsForColumn(column);
                const valueSuggestions = suggestionsForColumn(column);
                return (
                  <div key={condition.id} className="flex min-w-0 max-w-full items-center gap-2 max-sm:w-full max-sm:flex-wrap">
                    <div className="shrink-0 px-0.5 text-sm font-medium text-[color:var(--text-link)] max-sm:w-full">
                      {index === 0 ? 'Where' : 'And'}
                    </div>
                    <div className="flex min-w-0 max-w-full flex-1 items-stretch overflow-hidden rounded-md bg-[color:var(--bg-1)] text-sm ring-1 ring-inset ring-[color:var(--border)] max-sm:grid max-sm:w-full max-sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_2rem] sm:flex-none">
                      <div className="relative grid min-w-28 max-w-44 grid-cols-[1fr_2rem] max-sm:col-start-1 max-sm:row-start-1 max-sm:min-w-0 max-sm:max-w-none">
                        <select
                          name={`filter-${condition.id}-column`}
                          aria-label={`Filter ${index + 1} column`}
                          value={condition.column}
                          onChange={(event) => changeConditionColumn(condition.id, event.target.value)}
                          className="col-span-full row-start-1 min-w-0 appearance-none bg-transparent py-1.5 pl-2 pr-8 font-medium text-[color:var(--text-1)] outline-none"
                        >
                          {availableColumns.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
                        </select>
                        <ChevronDown size={16} strokeWidth={1.8} aria-hidden className="pointer-events-none col-start-2 row-start-1 place-self-center text-[color:var(--text-3)]" />
                      </div>
                      <div className="grid min-w-28 max-w-40 grid-cols-[1fr_2rem] border-l border-[color:var(--border)] bg-[color:var(--bg-3)] max-sm:col-start-2 max-sm:row-start-1 max-sm:min-w-0 max-sm:max-w-none">
                        <select
                          name={`filter-${condition.id}-operator`}
                          aria-label={`Filter ${index + 1} operator`}
                          value={condition.operator}
                          onChange={(event) => updateCondition(condition.id, { operator: event.target.value as QueryBuilderOperator })}
                          className="col-span-full row-start-1 min-w-0 appearance-none bg-transparent py-1.5 pl-2 pr-8 text-[color:var(--text-2)] outline-none"
                        >
                          {availableOperators.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                        </select>
                        <ChevronDown size={16} strokeWidth={1.8} aria-hidden className="pointer-events-none col-start-2 row-start-1 place-self-center text-[color:var(--text-3)]" />
                      </div>
                      {operator?.needsValue && (
                        <input
                          ref={(node) => {
                            if (node) valueInputRefs.current.set(condition.id, node);
                            else valueInputRefs.current.delete(condition.id);
                          }}
                          type={isNumericType(column?.type) ? 'number' : 'text'}
                          name={`filter-${condition.id}-value`}
                          aria-label={`Filter ${index + 1} value`}
                          list={valueSuggestions.length > 0 ? `filter-${condition.id}-suggestions` : undefined}
                          value={condition.value}
                          onChange={(event) => updateCondition(condition.id, { value: event.target.value })}
                          placeholder="Value"
                          className="h-8 min-w-20 flex-1 border-l border-[color:var(--border)] bg-transparent px-2 text-base text-[color:var(--text-1)] outline-none [appearance:textfield] placeholder:text-[color:var(--text-3)] focus:bg-[color:var(--bg-3)] max-sm:col-span-2 max-sm:col-start-1 max-sm:row-start-2 max-sm:w-full max-sm:border-l-0 max-sm:border-t sm:w-32 sm:text-sm [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
                        />
                      )}
                      {operator?.needsValue && valueSuggestions.length > 0 && (
                        <datalist id={`filter-${condition.id}-suggestions`}>
                          {valueSuggestions.map((value) => <option key={value} value={value} />)}
                        </datalist>
                      )}
                      <button
                        type="button"
                        onClick={() => setConditions((current) => current.filter((item) => item.id !== condition.id))}
                        className={cn(
                          'relative inline-flex size-8 shrink-0 items-center justify-center border-l border-[color:var(--border)] text-[color:var(--text-3)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--danger)]',
                          'max-sm:col-start-3 max-sm:row-start-1 max-sm:h-full',
                          operator?.needsValue && 'max-sm:row-span-2',
                          focusClass,
                        )}
                        aria-label={`Remove filter ${index + 1}`}
                      >
                        <X size={16} strokeWidth={1.8} aria-hidden />
                        <span className="pointer-events-none absolute left-1/2 top-1/2 size-[max(100%,3rem)] -translate-x-1/2 -translate-y-1/2 sm:hidden" aria-hidden />
                      </button>
                    </div>
                  </div>
                );
              })}

              </div>
            )}

            <div className="mt-2 flex min-w-0 items-center gap-2">

              <Popover.Root open={filterPickerOpen} onOpenChange={setFilterPickerOpen}>
                <Popover.Trigger asChild>
                  <button
                    type="button"
                    disabled={availableColumns.length === 0}
                    className={cn(
                      'relative inline-flex h-8 shrink-0 items-center justify-center rounded-md bg-[color:var(--bg-3)] text-sm font-medium text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)] hover:bg-[color:var(--border)] disabled:cursor-not-allowed disabled:opacity-40',
                      conditions.length === 0 ? 'gap-1.5 py-1.5 pr-2.5 pl-1.5' : 'w-8',
                      focusClass,
                    )}
                    aria-label="Add filter"
                  >
                    <Plus size={16} strokeWidth={2} aria-hidden className="shrink-0" />
                    {conditions.length === 0 && <span>Add filter</span>}
                    <span className="pointer-events-none absolute left-1/2 top-1/2 size-[max(100%,3rem)] -translate-x-1/2 -translate-y-1/2 sm:hidden" aria-hidden />
                  </button>
                </Popover.Trigger>
                <PickerSurface
                  className="w-[min(20rem,calc(100vw-2rem))]"
                  onCloseAutoFocus={(event) => {
                    if (pendingValueFocusId.current === null) return;
                    event.preventDefault();
                    const id = pendingValueFocusId.current;
                    pendingValueFocusId.current = null;
                    valueInputRefs.current.get(id)?.focus();
                  }}
                >
                  <PickerSearch id="query-filter-search" name="query-filter-search" value={filterSearch} onChange={setFilterSearch} placeholder="Search fields" />
                  <div className="max-h-72 overflow-y-auto p-1" role="list">
                    {recentFilterColumns.length > 0 && <PickerGroupLabel>Recent fields</PickerGroupLabel>}
                    {recentFilterColumns.map((column) => (
                      <FilterFieldOption
                        key={`recent-${column.name}`}
                        column={column}
                        onSelect={() => addCondition(column)}
                      />
                    ))}
                    {commonFilterColumns.length > 0 && <PickerGroupLabel>Common fields</PickerGroupLabel>}
                    {commonFilterColumns.map((column) => (
                      <FilterFieldOption
                        key={`common-${column.name}`}
                        column={column}
                        onSelect={() => addCondition(column)}
                      />
                    ))}
                    {remainingFilterColumns.length > 0 && (
                      <PickerGroupLabel>{recentFilterColumns.length > 0 || commonFilterColumns.length > 0 ? 'All fields' : 'Add a filter'}</PickerGroupLabel>
                    )}
                    {remainingFilterColumns.map((column) => (
                      <FilterFieldOption
                        key={column.name}
                        column={column}
                        onSelect={() => addCondition(column)}
                      />
                    ))}
                    {visibleFilterColumns.length === 0 && <p className="p-3 text-sm text-[color:var(--text-3)]">No fields match that search.</p>}
                  </div>
                </PickerSurface>
              </Popover.Root>

              {conditions.length > 0 && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className={cn('h-8 px-1 text-sm font-medium text-[color:var(--text-2)] hover:text-[color:var(--text-1)]', focusClass)}
                >
                  Clear filters
                </button>
              )}
            </div>
          </div>
        )}

        {!isLoading && !isError && (
          <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
            <p className="max-w-[72ch] text-base text-pretty text-[color:var(--text-3)] sm:text-sm">
              {selectedTable?.description || 'Choose a table, then add columns and filters.'}
            </p>
            {selectedTable?.url && (
              <a
                href={selectedTable.url}
                target="_blank"
                rel="noreferrer"
                className={cn('shrink-0 text-sm font-medium text-[color:var(--text-link)] hover:underline', focusClass)}
              >
                Table reference
              </a>
            )}
          </div>
        )}
      </section>

      <section className="flex flex-wrap items-center gap-3 border-t border-[color:var(--border)] px-4 py-3 sm:px-5" aria-label="Query result settings">
        {sortOpen ? (
          <div className="flex min-w-0 items-center overflow-hidden rounded-md bg-[color:var(--bg-1)] ring-1 ring-inset ring-[color:var(--border)]">
            <div className="flex h-8 shrink-0 items-center gap-1.5 px-2 text-sm text-[color:var(--text-3)]">
              <ArrowUpDown size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
              Sort
            </div>
            <CompactSelect value={orderBy} onChange={setOrderBy} name="query-builder-sort" ariaLabel="Sort results by column" className="min-w-36 border-l border-[color:var(--border)]">
              <option value="">Choose column</option>
              {availableColumns.map((column) => <option key={column.name} value={column.name}>{column.name}</option>)}
            </CompactSelect>
            {orderBy && (
              <CompactSelect value={orderDirection} onChange={(value) => setOrderDirection(value as 'ASC' | 'DESC')} name="query-builder-direction" ariaLabel="Sort direction" className="min-w-32 border-l border-[color:var(--border)] bg-[color:var(--bg-3)]">
                <option value="ASC">Ascending</option>
                <option value="DESC">Descending</option>
              </CompactSelect>
            )}
            <button
              type="button"
              onClick={() => {
                setOrderBy('');
                setOrderDirection('ASC');
                setSortOpen(false);
              }}
              className={cn(
                'relative inline-flex size-8 shrink-0 items-center justify-center border-l border-[color:var(--border)] text-[color:var(--text-3)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--danger)]',
                focusClass,
              )}
              aria-label="Remove sorting"
            >
              <X size={16} strokeWidth={1.8} aria-hidden />
              <span className="pointer-events-none absolute left-1/2 top-1/2 size-[max(100%,3rem)] -translate-x-1/2 -translate-y-1/2 sm:hidden" aria-hidden />
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setSortOpen(true)}
            className={cn(
              'inline-flex h-8 items-center gap-1.5 rounded-md py-1.5 pr-2.5 pl-1.5 text-sm font-medium text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
              focusClass,
            )}
          >
            <ArrowUpDown size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
            Add sorting
          </button>
        )}

        <label className="flex h-8 items-center overflow-hidden rounded-md bg-[color:var(--bg-1)] text-sm ring-1 ring-inset ring-[color:var(--border)]">
          <span className="px-2 text-[color:var(--text-3)]">Limit</span>
          <input
            type="number"
            name="query-builder-limit"
            aria-label="Row limit"
            min={1}
            max={10_000}
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
            className="h-8 w-24 border-l border-[color:var(--border)] bg-transparent px-2 text-base tabular-nums text-[color:var(--text-1)] outline-none [appearance:textfield] focus:bg-[color:var(--bg-3)] sm:text-sm [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
          />
        </label>

        {hasCustomQuery && (
          <button
            type="button"
            onClick={resetQuery}
            className={cn('h-8 px-1 text-sm font-medium text-[color:var(--text-2)] hover:text-[color:var(--text-1)]', focusClass)}
          >
            Reset query
          </button>
        )}

        {resetSnapshot && (
          <div role="status" className="flex h-8 items-center gap-2 rounded-md bg-[color:var(--bg-3)] px-2 text-sm text-[color:var(--text-2)]">
            Query reset.
            <button
              type="button"
              onClick={undoReset}
              className={cn('inline-flex items-center gap-1 font-medium text-[color:var(--text-link)] hover:underline', focusClass)}
            >
              <Undo2 size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
              Undo
            </button>
          </div>
        )}
      </section>

    </div>
  );
}
