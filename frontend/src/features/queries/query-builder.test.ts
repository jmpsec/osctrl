import { describe, expect, it } from 'vitest';
import type { OsqueryTable } from '$/api/types';
import { buildOsquerySql, type QueryBuilderState } from './query-builder';

const processes: OsqueryTable = {
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
};

function state(overrides: Partial<QueryBuilderState> = {}): QueryBuilderState {
  return {
    table: 'processes',
    columns: [],
    conditions: [],
    orderBy: '',
    orderDirection: 'ASC',
    limit: 100,
    ...overrides,
  };
}

describe('buildOsquerySql', () => {
  it('builds a safe default SELECT query', () => {
    expect(buildOsquerySql(state(), processes)).toBe(
      'SELECT *\nFROM processes\nLIMIT 100;',
    );
  });

  it('builds selected columns, typed filters, ordering, and a limit', () => {
    expect(buildOsquerySql(state({
      columns: ['pid', 'name'],
      conditions: [
        { id: 1, column: 'name', operator: 'contains', value: "worker's" },
        { id: 2, column: 'pid', operator: 'greater_than', value: '100' },
      ],
      orderBy: 'pid',
      orderDirection: 'DESC',
      limit: 25,
    }), processes)).toBe([
      'SELECT pid, name',
      'FROM processes',
      "WHERE name LIKE '%worker''s%'",
      '  AND pid > 100',
      'ORDER BY pid DESC',
      'LIMIT 25;',
    ].join('\n'));
  });

  it('omits incomplete value filters and supports null checks', () => {
    expect(buildOsquerySql(state({
      conditions: [
        { id: 1, column: 'path', operator: 'equals', value: '   ' },
        { id: 2, column: 'path', operator: 'is_not_null', value: '' },
      ],
    }), processes)).toContain('WHERE path IS NOT NULL');
    expect(buildOsquerySql(state({
      conditions: [{ id: 1, column: 'path', operator: 'equals', value: '   ' }],
    }), processes)).not.toContain('WHERE');
  });

  it('clamps the requested row limit', () => {
    expect(buildOsquerySql(state({ limit: 0 }), processes)).toContain('LIMIT 100;');
    expect(buildOsquerySql(state({ limit: 50_000 }), processes)).toContain('LIMIT 10000;');
  });
});
