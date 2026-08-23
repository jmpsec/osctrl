package activity

import (
	"fmt"
	"time"
)

// Default rollup settings and bucket layout.
const (
	DefaultPrefix        = "nodeact:v1"
	DefaultRetentionDays = 7
	BucketSeconds        = 3600
	BucketsPerDay        = 24
	// EventTypeCount sizes the per-day blob. New event types MUST be
	// appended to the end of the EventType list: bitOffset is linear in the
	// type index, so appending leaves every existing counter at the same
	// offset and only grows the blob. decodeDay is bounds-safe, so blobs
	// written before a new type existed simply decode it as zero — which is
	// why adding one needs no key-prefix bump and loses no history.
	EventTypeCount = 7
)

// EventType identifies the activity counter family stored in a bucket.
type EventType uint8

// Supported activity event types.
const (
	EventEnroll EventType = iota
	EventConfig
	EventStatus
	EventResult
	EventQueryRead
	EventQueryWrite
	// EventStatusError counts status logs the node reported at osquery's
	// ERROR severity. It is a subset of EventStatus, not a sibling: the
	// same log increments both, so it is deliberately left out of the
	// Total series to avoid counting one log twice.
	EventStatusError
)

// Event is one activity increment for a node at a specific point in time.
type Event struct {
	EnvUUID  string
	NodeUUID string
	Type     EventType
	At       time.Time
	Count    uint16
}

// NodeTileSeries is a dense activity series ready for node tile rendering.
type NodeTileSeries struct {
	Start         time.Time `json:"start"`
	BucketSeconds int       `json:"bucket_seconds"`
	Enroll        []uint16  `json:"enroll"`
	Config        []uint16  `json:"config"`
	Status        []uint16  `json:"status"`
	Result        []uint16  `json:"result"`
	QueryRead     []uint16  `json:"query_read"`
	QueryWrite    []uint16  `json:"query_write"`
	StatusError   []uint16  `json:"status_error"`
	Total         []uint16  `json:"total"`
}

// EnvSeries is a dense activity series ready for environment-level graphs.
type EnvSeries = NodeTileSeries

// DayKey returns the Redis key for one node's UTC activity day blob.
func DayKey(prefix, envUUID, nodeUUID string, day time.Time) string {
	return fmt.Sprintf("%s:%s:%s:%s", prefix, envUUID, nodeUUID, day.UTC().Format("20060102"))
}

// ErrorRankKey returns the Redis key for one environment's UTC day sorted set
// of per-node error counts.
//
// The hourly blobs are keyed per node, so answering "which nodes are erroring"
// from them alone would mean reading every node in the environment. This
// sorted set is the index for that question: ZINCRBY on write, ZREVRANGE on
// read, so the cost of the dashboard drill-down scales with the number of
// *erroring* nodes rather than the size of the fleet.
func ErrorRankKey(prefix, envUUID string, day time.Time) string {
	return fmt.Sprintf("%s:errs:%s:%s", prefix, envUUID, day.UTC().Format("20060102"))
}

// NodeErrorCount is one node's error tally over the requested window.
type NodeErrorCount struct {
	NodeUUID string `json:"node_uuid"`
	Errors   int64  `json:"errors"`
}

// EnvDayKey returns the Redis key for one environment's UTC activity day blob.
func EnvDayKey(prefix, envUUID string, day time.Time) string {
	return fmt.Sprintf("%s:env:%s:%s", prefix, envUUID, day.UTC().Format("20060102"))
}

func bucketHour(t time.Time) int {
	return t.UTC().Hour()
}

func dayStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func bitOffset(eventType EventType, hour int) int64 {
	return int64((int(eventType)*BucketsPerDay + hour) * 16)
}
