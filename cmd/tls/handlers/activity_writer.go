package handlers

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
	"github.com/rs/zerolog/log"
)

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
	if h == nil || h.ActivityWriter == nil || envUUID == "" || nodeUUID == "" {
		return
	}
	h.ActivityWriter.addEvent(activity.Event{
		EnvUUID:  envUUID,
		NodeUUID: nodeUUID,
		Type:     typ,
		At:       time.Now(),
		Count:    1,
	})
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
