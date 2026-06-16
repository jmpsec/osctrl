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
	EventTypeCount       = 6
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
	Total         []uint16  `json:"total"`
}

// DayKey returns the Redis key for one node's UTC activity day blob.
func DayKey(prefix, envUUID, nodeUUID string, day time.Time) string {
	return fmt.Sprintf("%s:%s:%s:%s", prefix, envUUID, nodeUUID, day.UTC().Format("20060102"))
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
