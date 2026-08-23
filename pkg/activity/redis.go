package activity

import (
	"context"
	"errors"
	"sort"
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

	type rankCounterKey struct {
		key      string
		nodeUUID string
	}

	aggregated := make(map[counterKey]uint32)
	ranked := make(map[rankCounterKey]int64)
	for _, event := range events {
		if event.EnvUUID == "" || event.Type >= EventTypeCount {
			continue
		}

		if event.Count == 0 {
			continue
		}

		offset := bitOffset(event.Type, bucketHour(event.At))
		if event.NodeUUID != "" {
			nodeKey := counterKey{
				key:    DayKey(s.prefix, event.EnvUUID, event.NodeUUID, event.At),
				offset: offset,
			}
			aggregated[nodeKey] += uint32(event.Count)
		}

		envKey := counterKey{
			key:    EnvDayKey(s.prefix, event.EnvUUID, event.At),
			offset: offset,
		}
		aggregated[envKey] += uint32(event.Count)

		// Errors additionally feed a per-env ranking so the dashboard can
		// name the offending nodes without walking the whole fleet. Only
		// errors pay this cost, and only when there are any.
		if event.Type == EventStatusError && event.NodeUUID != "" {
			rankKey := rankCounterKey{
				key:      ErrorRankKey(s.prefix, event.EnvUUID, event.At),
				nodeUUID: event.NodeUUID,
			}
			ranked[rankKey] += int64(event.Count)
		}
	}

	if len(aggregated) == 0 && len(ranked) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()
	expireKeys := make(map[string]struct{})
	for key, count := range aggregated {
		pipe.BitField(ctx, key.key, "OVERFLOW", "SAT", "INCRBY", "u16", key.offset, int64(count))
		expireKeys[key.key] = struct{}{}
	}
	for key, count := range ranked {
		pipe.ZIncrBy(ctx, key.key, float64(count), key.nodeUUID)
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
		out[nodeUUID] = newSeries(start, bucketCount)

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
		// Shared with ReadEnvSeries so a new event type only has to be
		// wired into one place — this loop used to be duplicated here and
		// silently missed counters added later.
		fillSeries(&series, fetch.dayIndex*BucketsPerDay, decoded)
		out[fetch.nodeUUID] = series
	}

	return out, nil
}

// ReadEnvSeries returns a dense environment activity series for the requested day window.
func (s *RedisStore) ReadEnvSeries(ctx context.Context, envUUID string, end time.Time, days int) (EnvSeries, error) {
	if days <= 0 {
		days = 1
	}

	start := dayStart(end).Add(-time.Duration(days-1) * 24 * time.Hour)
	bucketCount := days * BucketsPerDay
	series := newSeries(start, bucketCount)

	pipe := s.client.Pipeline()
	fetches := make([]*redis.StringCmd, 0, days)
	for dayIndex := 0; dayIndex < days; dayIndex++ {
		day := start.Add(time.Duration(dayIndex) * 24 * time.Hour)
		fetches = append(fetches, pipe.Get(ctx, EnvDayKey(s.prefix, envUUID, day)))
	}

	if len(fetches) == 0 {
		return series, nil
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return EnvSeries{}, err
	}

	for dayIndex, cmd := range fetches {
		blob, err := cmd.Bytes()
		if err != nil && !errors.Is(err, redis.Nil) {
			return EnvSeries{}, err
		}
		if len(blob) == 0 {
			continue
		}

		fillSeries(&series, dayIndex*BucketsPerDay, decodeDay(blob))
	}

	return series, nil
}

func newSeries(start time.Time, bucketCount int) NodeTileSeries {
	return NodeTileSeries{
		Start:         start,
		BucketSeconds: BucketSeconds,
		Enroll:        make([]uint16, bucketCount),
		Config:        make([]uint16, bucketCount),
		Status:        make([]uint16, bucketCount),
		Result:        make([]uint16, bucketCount),
		QueryRead:     make([]uint16, bucketCount),
		QueryWrite:    make([]uint16, bucketCount),
		StatusError:   make([]uint16, bucketCount),
		Total:         make([]uint16, bucketCount),
	}
}

func fillSeries(series *NodeTileSeries, base int, decoded [EventTypeCount][BucketsPerDay]uint16) {
	for hour := 0; hour < BucketsPerDay; hour++ {
		idx := base + hour
		series.Enroll[idx] = decoded[EventEnroll][hour]
		series.Config[idx] = decoded[EventConfig][hour]
		series.Status[idx] = decoded[EventStatus][hour]
		series.Result[idx] = decoded[EventResult][hour]
		series.QueryRead[idx] = decoded[EventQueryRead][hour]
		series.QueryWrite[idx] = decoded[EventQueryWrite][hour]
		series.StatusError[idx] = decoded[EventStatusError][hour]
		// EventStatusError is intentionally absent from Total: it is a
		// subset of EventStatus, and including it would count an erroring
		// status log twice in the activity heatmap.
		series.Total[idx] = saturatingSum(
			decoded[EventEnroll][hour],
			decoded[EventConfig][hour],
			decoded[EventStatus][hour],
			decoded[EventResult][hour],
			decoded[EventQueryRead][hour],
			decoded[EventQueryWrite][hour],
		)
	}
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

// TopErrorNodes returns the nodes with the most ERROR-severity status logs in
// the requested window, worst first, capped at limit.
//
// The window is expressed in whole UTC days because that is how the counters
// are bucketed; a 24h view spans at most two of them. Each day's ranking is
// read in full and merged here — bounded by the number of nodes that actually
// errored, which is the small number in any fleet worth alerting on.
func (s *RedisStore) TopErrorNodes(ctx context.Context, envUUID string, end time.Time, days, limit int) ([]NodeErrorCount, error) {
	if days <= 0 {
		days = 1
	}
	if limit <= 0 {
		limit = 10
	}

	start := dayStart(end).Add(-time.Duration(days-1) * 24 * time.Hour)
	pipe := s.client.Pipeline()
	cmds := make([]*redis.ZSliceCmd, 0, days)
	for dayIndex := 0; dayIndex < days; dayIndex++ {
		day := start.Add(time.Duration(dayIndex) * 24 * time.Hour)
		cmds = append(cmds, pipe.ZRevRangeWithScores(ctx, ErrorRankKey(s.prefix, envUUID, day), 0, -1))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	totals := make(map[string]int64)
	for _, cmd := range cmds {
		entries, err := cmd.Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			nodeUUID, ok := entry.Member.(string)
			if !ok || nodeUUID == "" || entry.Score <= 0 {
				continue
			}
			totals[nodeUUID] += int64(entry.Score)
		}
	}

	out := make([]NodeErrorCount, 0, len(totals))
	for nodeUUID, errCount := range totals {
		out = append(out, NodeErrorCount{NodeUUID: nodeUUID, Errors: errCount})
	}
	// Worst first; ties broken by UUID so the list is stable between polls
	// and does not shuffle under the operator's cursor.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Errors == out[j].Errors {
			return out[i].NodeUUID < out[j].NodeUUID
		}
		return out[i].Errors > out[j].Errors
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
