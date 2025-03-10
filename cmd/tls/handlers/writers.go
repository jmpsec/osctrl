package handlers

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
)

// writeEvent represents a single update request.
type writeEvent struct {
	NodeID uint
	IP     string
}

// batchWriter encapsulates the batching logic.
type batchWriter struct {
	events    chan writeEvent
	batchSize int           // minimum number of events before flushing
	timeout   time.Duration // maximum wait time before flushing
	nodesRepo nodes.NodeManager
}

// NewBatchWriter creates and starts a new batch writer.
func NewBatchWriter(batchSize int, timeout time.Duration, bufferSize int, repo nodes.NodeManager) *batchWriter {
	bw := &batchWriter{
		events:    make(chan writeEvent, bufferSize), // buffer size as needed
		batchSize: batchSize,
		timeout:   timeout,
		nodesRepo: repo,
	}
	go bw.run()
	return bw
}

// addEvent sends a new write event to the batch writer.
func (bw *batchWriter) addEvent(ev writeEvent) {
	bw.events <- ev
}

// run is the background worker that collects and flushes events.
func (bw *batchWriter) run() {
	batch := make(map[uint]writeEvent)
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
				batch = make(map[uint]writeEvent)
				timer.Reset(bw.timeout)
			}
		case <-timer.C:
			if len(batch) > 0 {
				bw.flush(batch)
				batch = make(map[uint]writeEvent)
			}
			timer.Reset(bw.timeout)
		}
	}
}

// flush performs the bulk update for a batch of events.
func (bw *batchWriter) flush(batch map[uint]writeEvent) {

	nodeIDs := make([]uint, 0, len(batch))
	for _, ev := range batch {
		nodeIDs = append(nodeIDs, ev.NodeID)

		// TODO: Implement the actual update logic.
		// Update the node's IP address.
		// Since the IP address changes infrequently, no need to update in bulk.
	}
	log.Info().Int("count", len(batch)).Msg("flushed batch")
	if err := bw.nodesRepo.RefreshLastSeenBatch(nodeIDs); err != nil {
		log.Err(err).Msg("refreshing last seen batch failed")
	}
}
