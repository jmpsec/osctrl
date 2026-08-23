import { describe, expect, it } from 'vitest';
import type { NodeActivityBucket, NodeTileSeries } from '$/api/stats';
import { mergeNodeActivityBuckets } from './NodeDetailPage';

describe('mergeNodeActivityBuckets', () => {
  it('folds query read and write tile activity into the query heatmap row', () => {
    const buckets: NodeActivityBucket[] = [
      {
        bucket_start: '2026-07-02T10:00:00Z',
        status: 0,
        result: 0,
        query: 0,
        carve: 0,
        config: 0,
      },
      {
        bucket_start: '2026-07-02T11:00:00Z',
        status: 0,
        result: 0,
        query: 0,
        carve: 0,
        config: 0,
      },
    ];

    const tiles: NodeTileSeries = {
      start: '2026-07-02T10:00:00Z',
      bucket_seconds: 3600,
      enroll: [0, 0],
      status_error: [0, 0],
      config: [0, 0],
      status: [0, 0],
      result: [0, 0],
      query_read: [2, 0],
      query_write: [0, 3],
      total: [2, 3],
    };

    const merged = mergeNodeActivityBuckets(buckets, tiles);

    expect(merged.map((b) => b.query)).toEqual([2, 3]);
  });

  // The errors row is fed from the Redis series, aligned the same way config
  // is, and must not be folded into any other row.
  it('folds status errors into their own heatmap row', () => {
    const buckets: NodeActivityBucket[] = [
      { bucket_start: '2026-07-02T10:00:00Z', status: 5, result: 0, query: 0, carve: 0, config: 0 },
      { bucket_start: '2026-07-02T11:00:00Z', status: 7, result: 0, query: 0, carve: 0, config: 0 },
    ];

    const tiles: NodeTileSeries = {
      start: '2026-07-02T10:00:00Z',
      bucket_seconds: 3600,
      enroll: [0, 0],
      status_error: [2, 4],
      config: [0, 0],
      status: [5, 7],
      result: [0, 0],
      query_read: [0, 0],
      query_write: [0, 0],
      total: [5, 7],
    };

    const merged = mergeNodeActivityBuckets(buckets, tiles);

    expect(merged.map((b) => b.error)).toEqual([2, 4]);
    // The status row keeps reporting the node's own status count: errors are
    // a subset of it, not extra traffic to add on top.
    expect(merged.map((b) => b.status)).toEqual([5, 7]);
    expect(merged.map((b) => b.query)).toEqual([0, 0]);
  });

  // A series from a server predating the counter omits the field entirely;
  // the row must read zero rather than throw or shift the other rows.
  it('reads zero errors when the series omits the counter', () => {
    const buckets: NodeActivityBucket[] = [
      { bucket_start: '2026-07-02T10:00:00Z', status: 1, result: 0, query: 0, carve: 0, config: 0 },
    ];

    const tiles = {
      start: '2026-07-02T10:00:00Z',
      bucket_seconds: 3600,
      enroll: [0],
      config: [3],
      status: [1],
      result: [0],
      query_read: [0],
      query_write: [0],
      total: [1],
    } as unknown as NodeTileSeries;

    const merged = mergeNodeActivityBuckets(buckets, tiles);

    expect(merged.map((b) => b.error)).toEqual([0]);
    // The rest of the merge still works off the remaining series.
    expect(merged.map((b) => b.config)).toEqual([3]);
  });
});
