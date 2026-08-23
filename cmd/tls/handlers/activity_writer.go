package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// osquerySeverityError is osquery's ERROR level on the 0=INFO, 1=WARNING,
// 2=ERROR status-log ladder.
const osquerySeverityError types.StringInt = 2

type activityStore interface {
	IncrementMany(ctx context.Context, events []activity.Event) error
}

type activityWriter struct {
	store     activityStore
	events    chan activity.Event
	batchSize int
	timeout   time.Duration
	stop      chan struct{}
	done      chan struct{}
}

func NewActivityWriter(store activityStore, batchSize int, timeout time.Duration, bufferSize int) *activityWriter {
	if store == nil {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 1
	}
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	if bufferSize <= 0 {
		bufferSize = batchSize
	}

	aw := &activityWriter{
		store:     store,
		events:    make(chan activity.Event, bufferSize),
		batchSize: batchSize,
		timeout:   timeout,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go aw.run()

	return aw
}

func (aw *activityWriter) addEvent(ev activity.Event) {
	if aw == nil {
		return
	}

	select {
	case aw.events <- ev:
	default:
		log.Warn().
			Str("env", ev.EnvUUID).
			Str("node", ev.NodeUUID).
			Msg("dropping node activity event because writer queue is full")
	}
}

func (aw *activityWriter) close() {
	if aw == nil {
		return
	}

	select {
	case <-aw.done:
		return
	default:
	}

	close(aw.stop)
	<-aw.done
}

func (aw *activityWriter) run() {
	defer close(aw.done)

	batch := make([]activity.Event, 0, aw.batchSize)
	timer := time.NewTimer(aw.timeout)
	defer timer.Stop()

	for {
		select {
		case <-aw.stop:
			aw.flush(aw.drain(batch))
			return
		case ev := <-aw.events:
			batch = append(batch, ev)
			if len(batch) >= aw.batchSize {
				aw.flush(batch)
				batch = batch[:0]
				resetTimer(timer, aw.timeout)
			}
		case <-timer.C:
			if len(batch) > 0 {
				aw.flush(batch)
				batch = batch[:0]
			}
			timer.Reset(aw.timeout)
		}
	}
}

func (aw *activityWriter) drain(batch []activity.Event) []activity.Event {
	for {
		select {
		case ev := <-aw.events:
			batch = append(batch, ev)
		default:
			return batch
		}
	}
}

func (aw *activityWriter) flush(batch []activity.Event) {
	if len(batch) == 0 {
		return
	}

	type eventKey struct {
		envUUID   string
		nodeUUID  string
		eventType activity.EventType
		at        time.Time
	}

	counts := make(map[eventKey]uint32, len(batch))
	for _, ev := range batch {
		if ev.EnvUUID == "" || ev.NodeUUID == "" || ev.Type >= activity.EventTypeCount {
			continue
		}

		if ev.Count == 0 {
			ev.Count = 1
		}

		at := ev.At.UTC().Truncate(time.Hour)
		key := eventKey{
			envUUID:   ev.EnvUUID,
			nodeUUID:  ev.NodeUUID,
			eventType: ev.Type,
			at:        at,
		}
		counts[key] += uint32(ev.Count)
	}

	if len(counts) == 0 {
		return
	}

	events := make([]activity.Event, 0, len(counts))
	for key, count := range counts {
		if count > uint32(^uint16(0)) {
			count = uint32(^uint16(0))
		}
		events = append(events, activity.Event{
			EnvUUID:  key.envUUID,
			NodeUUID: key.nodeUUID,
			Type:     key.eventType,
			At:       key.at,
			Count:    uint16(count),
		})
	}

	if err := aw.store.IncrementMany(context.Background(), events); err != nil {
		log.Err(err).Msg("flushing node activity rollups failed")
	}
}

func resetTimer(timer *time.Timer, timeout time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
}

// recordActivity emits one per-endpoint activity counter to the Redis rollup
// store. It is fire-and-forget: a nil writer, a nil handler, or empty
// env/node UUIDs are silently skipped so it can never block or fail the
// request path. The counters feed the per-node/per-env activity heatmaps
// surfaced in the admin frontend.
func (h *HandlersTLS) recordActivity(envUUID, nodeUUID string, typ activity.EventType) {
	h.recordActivityCount(envUUID, nodeUUID, typ, 1)
}

// recordActivityCount is recordActivity for counters that advance by more than
// one per request — a single status POST carries a batch of log lines, so the
// error counter moves by however many of them osquery flagged. Same
// fire-and-forget contract: it can never block or fail the request path.
func (h *HandlersTLS) recordActivityCount(envUUID, nodeUUID string, typ activity.EventType, count uint16) {
	if h == nil || h.ActivityWriter == nil || envUUID == "" || nodeUUID == "" || count == 0 {
		return
	}
	h.ActivityWriter.addEvent(activity.Event{
		EnvUUID:  envUUID,
		NodeUUID: nodeUUID,
		Type:     typ,
		At:       time.Now(),
		Count:    count,
	})
}

// countStatusErrors reports how many entries in a status-log batch osquery
// flagged at ERROR severity.
//
// Only ERROR counts. osquery's severity ladder is 0=INFO, 1=WARNING,
// 2=ERROR, and warnings are common enough in normal operation (a table that
// is unavailable on this platform, a transient permission issue) that
// counting them would keep the dashboard permanently amber and train
// operators to ignore it.
//
// A malformed batch yields 0 rather than an error: this feeds a dashboard
// counter, and losing a count is strictly better than failing log ingestion.
// The parse is deliberately narrow — only the severity field is decoded, so
// the cost is a fraction of the full ProcessLogs pass it runs alongside.
func countStatusErrors(data json.RawMessage) uint16 {
	var entries []struct {
		Severity types.StringInt `json:"severity"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0
	}
	var errors int
	for _, entry := range entries {
		if entry.Severity == osquerySeverityError {
			errors++
		}
	}
	// Counters are uint16 in the rollup blob; saturate rather than wrap, so
	// an implausibly large batch reads as "very many" instead of "a few".
	if errors > int(^uint16(0)) {
		return ^uint16(0)
	}
	return uint16(errors)
}

// logActivityType maps an osquery log type ("status"/"result") to its
// activity counter family. Unknown types return ok=false and are not
// recorded, so a malformed body cannot poison the rollups.
func logActivityType(logType string) (activity.EventType, bool) {
	switch logType {
	case "status":
		return activity.EventStatus, true
	case "result":
		return activity.EventResult, true
	default:
		return 0, false
	}
}
