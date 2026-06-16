package activity

import (
	"context"
	"errors"
	"time"

	redis "github.com/go-redis/redis/v8"
)

// RedisStore manages node activity rollups stored as compact Redis day blobs.
type RedisStore struct {
	client      *redis.Client
	prefix      string
	expireAfter time.Duration
}

// NewRedisStore builds a Redis-backed rollup store for per-node activity tiles.
func NewRedisStore(client *redis.Client, prefix string, retentionDays int, expireAfter time.Duration) *RedisStore {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	if retentionDays <= 0 {
		retentionDays = DefaultRetentionDays
	}
	if expireAfter <= 0 {
		expireAfter = time.Duration(retentionDays+1) * 24 * time.Hour
	}

	return &RedisStore{
		client:      client,
		prefix:      prefix,
		expireAfter: expireAfter,
	}
}

// IncrementMany batches activity events into hourly counters per UTC day.
func (s *RedisStore) IncrementMany(ctx context.Context, events []Event) error {
	type counterKey struct {
		key    string
		offset int64
	}

	aggregated := make(map[counterKey]uint32)
	for _, event := range events {
		if event.EnvUUID == "" || event.NodeUUID == "" || event.Type >= EventTypeCount {
			continue
		}

		if event.Count == 0 {
			continue
		}

		key := counterKey{
			key:    DayKey(s.prefix, event.EnvUUID, event.NodeUUID, event.At),
			offset: bitOffset(event.Type, bucketHour(event.At)),
		}
		aggregated[key] += uint32(event.Count)
	}

	if len(aggregated) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()
	expireKeys := make(map[string]struct{})
	for key, count := range aggregated {
		pipe.BitField(ctx, key.key, "OVERFLOW", "SAT", "INCRBY", "u16", key.offset, int64(count))
		expireKeys[key.key] = struct{}{}
	}
	for key := range expireKeys {
		pipe.Expire(ctx, key, s.expireAfter)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// ReadSeries returns dense node activity series for the requested day window.
func (s *RedisStore) ReadSeries(ctx context.Context, envUUID string, nodeUUIDs []string, end time.Time, days int) (map[string]NodeTileSeries, error) {
	if days <= 0 {
		days = 1
	}

	start := dayStart(end).Add(-time.Duration(days-1) * 24 * time.Hour)
	bucketCount := days * BucketsPerDay
	out := make(map[string]NodeTileSeries, len(nodeUUIDs))

	type dayFetch struct {
		nodeUUID string
		dayIndex int
		cmd      *redis.StringCmd
	}

	pipe := s.client.Pipeline()
	fetches := make([]dayFetch, 0, len(nodeUUIDs)*days)
	for _, nodeUUID := range nodeUUIDs {
		out[nodeUUID] = NodeTileSeries{
			Start:         start,
			BucketSeconds: BucketSeconds,
			Enroll:        make([]uint16, bucketCount),
			Config:        make([]uint16, bucketCount),
			Status:        make([]uint16, bucketCount),
			Result:        make([]uint16, bucketCount),
			QueryRead:     make([]uint16, bucketCount),
			QueryWrite:    make([]uint16, bucketCount),
			Total:         make([]uint16, bucketCount),
		}

		for dayIndex := 0; dayIndex < days; dayIndex++ {
			day := start.Add(time.Duration(dayIndex) * 24 * time.Hour)
			cmd := pipe.Get(ctx, DayKey(s.prefix, envUUID, nodeUUID, day))
			fetches = append(fetches, dayFetch{
				nodeUUID: nodeUUID,
				dayIndex: dayIndex,
				cmd:      cmd,
			})
		}
	}

	if len(fetches) == 0 {
		return out, nil
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	for _, fetch := range fetches {
		blob, err := fetch.cmd.Bytes()
		if err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}
		if len(blob) == 0 {
			continue
		}

		decoded := decodeDay(blob)
		series := out[fetch.nodeUUID]
		base := fetch.dayIndex * BucketsPerDay
		for hour := 0; hour < BucketsPerDay; hour++ {
			idx := base + hour
			series.Enroll[idx] = decoded[EventEnroll][hour]
			series.Config[idx] = decoded[EventConfig][hour]
			series.Status[idx] = decoded[EventStatus][hour]
			series.Result[idx] = decoded[EventResult][hour]
			series.QueryRead[idx] = decoded[EventQueryRead][hour]
			series.QueryWrite[idx] = decoded[EventQueryWrite][hour]
			series.Total[idx] = saturatingSum(
				decoded[EventEnroll][hour],
				decoded[EventConfig][hour],
				decoded[EventStatus][hour],
				decoded[EventResult][hour],
				decoded[EventQueryRead][hour],
				decoded[EventQueryWrite][hour],
			)
		}
		out[fetch.nodeUUID] = series
	}

	return out, nil
}

func decodeDay(blob []byte) [EventTypeCount][BucketsPerDay]uint16 {
	var out [EventTypeCount][BucketsPerDay]uint16

	for eventType := 0; eventType < EventTypeCount; eventType++ {
		for hour := 0; hour < BucketsPerDay; hour++ {
			base := (eventType*BucketsPerDay + hour) * 2
			if base+1 >= len(blob) {
				continue
			}
			out[eventType][hour] = uint16(blob[base])<<8 | uint16(blob[base+1])
		}
	}

	return out
}

func saturatingSum(values ...uint16) uint16 {
	var total uint32
	for _, value := range values {
		total += uint32(value)
		if total > uint32(^uint16(0)) {
			return ^uint16(0)
		}
	}

	return uint16(total)
}
