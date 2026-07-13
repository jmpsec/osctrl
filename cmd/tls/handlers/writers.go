package handlers

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
)

// lastSeenUpdate represents a single update request.
type lastSeenUpdate struct {
	NodeID uint
	IP     string
	// SeenAt is when the node actually checked in. Stored per-event so
	// the batch flush doesn't stamp every node with the same wall-clock
	// time — without this, all nodes in a batch show identical last_seen
	// values in the UI, masking per-node check-in cadence.
	SeenAt time.Time
}

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
			// Overwrite any existing event for the same NodeID.
			batch[ev.NodeID] = ev

			// Flush if we have reached the batch size threshold.
			if len(batch) >= bw.batchSize {
				if !timer.Stop() {
					<-timer.C // drain the timer channel if necessary
				}
				bw.flush(batch)
				batch = make(map[uint]lastSeenUpdate)
				timer.Reset(bw.timeout)
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

// flush performs the bulk update for a batch of events.
func (bw *batchWriter) flush(batch map[uint]lastSeenUpdate) {
	start := time.Now()
	batchSize := len(batch)

	for _, ev := range batch {
		// Update the node's IP address.
		// Since the IP address changes infrequently, no need to update in bulk.
		if ev.IP != "" {
			ipStart := time.Now()
			if err := bw.nodesRepo.UpdateIP(ev.NodeID, ev.IP); err != nil {
				log.Err(err).Uint("node_id", ev.NodeID).Str("ip", ev.IP).Msg("updating IP failed")
			}
			ipDuration := time.Since(ipStart).Seconds()
			batchFlushDuration.WithLabelValues("ip_update").Observe(ipDuration)
		}
	}

	log.Info().Int("count", batchSize).Msg("flushing batch")

	// Update last_seen per-node with each event's actual check-in time.
	// The old RefreshLastSeenBatch stamped every node in the batch with the
	// same time.Now(), making all nodes appear to check in simultaneously.
	lastSeenStart := time.Now()
	for _, ev := range batch {
		seenAt := ev.SeenAt
		if seenAt.IsZero() {
			seenAt = time.Now()
		}
		if err := bw.nodesRepo.UpdateLastSeen(ev.NodeID, seenAt); err != nil {
			log.Err(err).Uint("node_id", ev.NodeID).Msg("updating last_seen failed")
		}
	}
	lastSeenDuration := time.Since(lastSeenStart).Seconds()

	// Record total flush duration and batch last_seen update duration
	totalDuration := time.Since(start).Seconds()
	batchFlushDuration.WithLabelValues("total").Observe(totalDuration)
	batchFlushDuration.WithLabelValues("last_seen_update").Observe(lastSeenDuration)

	log.Info().
		Int("count", batchSize).
		Float64("duration_seconds", totalDuration).
		Float64("last_seen_update_seconds", lastSeenDuration).
		Msg("batch flush completed")
}
