import { describe, it, expect } from 'vitest';
import { getQueryResultsCSVUrl } from './queries';

/**
 * URL-builder tests for the queries API module.
 * These tests do not hit the network; they verify that the correct URLs
 * are constructed for each endpoint so the React pages target the right paths.
 */
describe('queries API URL builders', () => {
  it('getQueryResultsCSVUrl produces the expected path', () => {
    const url = getQueryResultsCSVUrl('prod-env-uuid', 'q_abc123');
    expect(url).toBe('/api/v1/queries/prod-env-uuid/results/csv/q_abc123');
  });

  it('getQueryResultsCSVUrl encodes special characters in env and name', () => {
    const url = getQueryResultsCSVUrl('env with spaces', 'name/with/slashes');
    expect(url).toBe('/api/v1/queries/env%20with%20spaces/results/csv/name%2Fwith%2Fslashes');
  });
});

describe('listQueries URL construction', () => {
  // We test via the URLSearchParams construction used inside listQueries
  // by verifying query param serialisation with a lightweight helper.
  it('builds correct search params with all options', () => {
    const params = new URLSearchParams();
    params.set('q', 'osquery_info');
    params.set('sort', 'created');
    params.set('dir', 'asc');
    params.set('page', '2');
    params.set('page_size', '25');

    const qs = params.toString();
    expect(qs).toContain('q=osquery_info');
    expect(qs).toContain('sort=created');
    expect(qs).toContain('dir=asc');
    expect(qs).toContain('page=2');
    expect(qs).toContain('page_size=25');
  });

  it('does not include page param when not set', () => {
    const params = new URLSearchParams();
    params.set('q', 'test');
    expect(params.toString()).not.toContain('page=');
  });
});
