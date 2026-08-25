import type { OsqueryTable } from '$/api/types';

export type QueryBuilderOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'starts_with'
  | 'greater_than'
  | 'greater_or_equal'
  | 'less_than'
  | 'less_or_equal'
  | 'is_null'
  | 'is_not_null';

export interface QueryBuilderCondition {
  id: number;
  column: string;
  operator: QueryBuilderOperator;
  value: string;
}

export interface QueryBuilderState {
  table: string;
  columns: string[];
  conditions: QueryBuilderCondition[];
  orderBy: string;
  orderDirection: 'ASC' | 'DESC';
  limit: number;
}

const NUMERIC_TYPES = new Set([
  'bigint',
  'double',
  'float',
  'int',
  'integer',
  'smallint',
  'unsigned_bigint',
]);

function identifier(value: string): string {
  return /^[a-z_][a-z0-9_]*$/i.test(value)
    ? value
    : `"${value.replaceAll('"', '""')}"`;
}

function stringLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function literal(value: string, columnType: string | undefined): string {
  const trimmed = value.trim();
  if (columnType && NUMERIC_TYPES.has(columnType.toLowerCase()) && /^-?\d+(?:\.\d+)?$/.test(trimmed)) {
    return trimmed;
  }
  return stringLiteral(value);
}

function conditionSql(
  condition: QueryBuilderCondition,
  table: OsqueryTable | undefined,
): string | null {
  if (!condition.column) return null;

  const column = identifier(condition.column);
  if (condition.operator === 'is_null') return `${column} IS NULL`;
  if (condition.operator === 'is_not_null') return `${column} IS NOT NULL`;
  if (condition.value.trim() === '') return null;

  const type = table?.columns?.find((item) => item.name === condition.column)?.type;
  const value = literal(condition.value, type);

  switch (condition.operator) {
    case 'equals':
      return `${column} = ${value}`;
    case 'not_equals':
      return `${column} != ${value}`;
    case 'contains':
      return `${column} LIKE ${stringLiteral(`%${condition.value}%`)}`;
    case 'starts_with':
      return `${column} LIKE ${stringLiteral(`${condition.value}%`)}`;
    case 'greater_than':
      return `${column} > ${value}`;
    case 'greater_or_equal':
      return `${column} >= ${value}`;
    case 'less_than':
      return `${column} < ${value}`;
    case 'less_or_equal':
      return `${column} <= ${value}`;
  }
}

export function buildOsquerySql(
  state: QueryBuilderState,
  table?: OsqueryTable,
): string {
  const columns = state.columns.length > 0
    ? state.columns.map(identifier).join(', ')
    : '*';
  const lines = [`SELECT ${columns}`, `FROM ${identifier(state.table || 'osquery_info')}`];
  const conditions = state.conditions
    .map((condition) => conditionSql(condition, table))
    .filter((condition): condition is string => Boolean(condition));

  if (conditions.length > 0) {
    lines.push(`WHERE ${conditions.join('\n  AND ')}`);
  }
  if (state.orderBy) {
    lines.push(`ORDER BY ${identifier(state.orderBy)} ${state.orderDirection}`);
  }

  const limit = Math.min(10_000, Math.max(1, Math.round(state.limit || 100)));
  lines.push(`LIMIT ${limit};`);
  return lines.join('\n');
}

export const QUERY_BUILDER_OPERATORS: Array<{
  value: QueryBuilderOperator;
  label: string;
  needsValue: boolean;
}> = [
  { value: 'equals', label: 'equals', needsValue: true },
  { value: 'not_equals', label: 'does not equal', needsValue: true },
  { value: 'contains', label: 'contains', needsValue: true },
  { value: 'starts_with', label: 'starts with', needsValue: true },
  { value: 'greater_than', label: 'is greater than', needsValue: true },
  { value: 'greater_or_equal', label: 'is at least', needsValue: true },
  { value: 'less_than', label: 'is less than', needsValue: true },
  { value: 'less_or_equal', label: 'is at most', needsValue: true },
  { value: 'is_null', label: 'is empty', needsValue: false },
  { value: 'is_not_null', label: 'is not empty', needsValue: false },
];
