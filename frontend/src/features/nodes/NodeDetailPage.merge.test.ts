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
      },
      {
        bucket_start: '2026-07-02T11:00:00Z',
        status: 0,
        result: 0,
        query: 0,
        carve: 0,
      },
    ];

    const tiles: NodeTileSeries = {
      start: '2026-07-02T10:00:00Z',
      bucket_seconds: 3600,
      enroll: [0, 0],
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
});
