package handlers

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
)

// lastSeenUpdate represents a single update request.
type lastSeenUpdate = nodes.Checkin

// batchWriter encapsulates the batching logic.
type batchWriter struct {
	events    chan lastSeenUpdate
	batchSize int
	timeout   time.Duration // maximum wait time before flushing
	nodesRepo nodes.NodeManager
}

// NewBatchWriter creates and starts a new batch writer.
func NewBatchWriter(batchSize int, timeout time.Duration, bufferSize int, repo nodes.NodeManager) *batchWriter {
	bw := &batchWriter{
		events:    make(chan lastSeenUpdate, bufferSize),
		batchSize: batchSize,
		timeout:   timeout,
		nodesRepo: repo,
	}
	go bw.run()
	return bw
}

// addEvent sends a new write event to the batch writer.
func (bw *batchWriter) addEvent(ev lastSeenUpdate) {
	if ev.SeenAt.IsZero() {
		ev.SeenAt = time.Now()
	}
	bw.events <- ev
}

// run is the background worker that collects and flushes events.
func (bw *batchWriter) run() {
	batch := make(map[uint]lastSeenUpdate)
	timer := time.NewTimer(bw.timeout)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-bw.events:
			if !ok {
				// Channel closed: flush any remaining events.
				if len(batch) > 0 {
					bw.flush(batch)
				}
				return
			}
			mergeCheckin(batch, ev)

			// Flush if we have reached the batch size threshold.
			if len(batch) >= bw.batchSize {
				timer.Stop()
				bw.flush(batch)
				batch = make(map[uint]lastSeenUpdate)
				resetTimer(timer, bw.timeout)
			}
		case <-timer.C:
			if len(batch) > 0 {
				bw.flush(batch)
				batch = make(map[uint]lastSeenUpdate)
			}
			timer.Reset(bw.timeout)
		}
	}
}

func mergeCheckin(batch map[uint]lastSeenUpdate, ev lastSeenUpdate) {
	previous := batch[ev.NodeID]
	if ev.SeenAt.Before(previous.SeenAt) {
		return
	}
	batch[ev.NodeID] = ev
}

// flush performs the bulk update for a batch of events.
func (bw *batchWriter) flush(batch map[uint]lastSeenUpdate) {
	start := time.Now()
	if err := bw.nodesRepo.UpdateCheckins(batch); err != nil {
		log.Err(err).Int("count", len(batch)).Msg("updating node check-ins failed")
	}
	totalDuration := time.Since(start).Seconds()
	batchFlushDuration.WithLabelValues("total").Observe(totalDuration)
	batchFlushDuration.WithLabelValues("last_seen_update").Observe(totalDuration)
	log.Debug().Int("count", len(batch)).Float64("duration_seconds", totalDuration).
		Msg("batch flush completed")
}
