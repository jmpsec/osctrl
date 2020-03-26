package handlers

import (
	"log"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/types"
)

// ProcessCarveInit - Function to initialize a file carve from a node
func (h *HandlersTLS) ProcessCarveInit(req types.CarveInitRequest, sessionid, environment string) error {
	// Retrieve node
	node, err := h.Nodes.GetByKey(req.NodeKey)
	if err != nil {
		h.Inc(metricInitErr)
		log.Printf("error retrieving node %s", err)
		return err
	}
	// Prepare carve to initialize
	carve := carves.CarvedFile{
		CarveID:         req.CarveID,
		RequestID:       req.RequestID,
		SessionID:       sessionid,
		UUID:            node.UUID,
		Environment:     environment,
		CarveSize:       req.CarveSize,
		BlockSize:       req.BlockSize,
		TotalBlocks:     req.BlockCount,
		CompletedBlocks: 0,
		Status:          carves.StatusInitialized,
	}
	// Create File Carve
	err = h.Carves.CreateCarve(carve)
	if err != nil {
		h.Inc(metricInitErr)
		log.Printf("error creating  CarvedFile %v", err)
		return err
	}
	return nil
}

// ProcessCarveBlock - Function to process one block from a file carve
// FIXME it can be more efficient on db access
func (h *HandlersTLS) ProcessCarveBlock(req types.CarveBlockRequest, environment string) {
	// Prepare carve block
	block := carves.CarvedBlock{
		RequestID:   req.RequestID,
		SessionID:   req.SessionID,
		Environment: environment,
		BlockID:     req.BlockID,
		Data:        req.Data,
		Size:        len(req.Data),
	}
	// Create Block
	if err := h.Carves.CreateBlock(block); err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error creating CarvedBlock %v", err)
	}
	// Bump block completion
	if err := h.Carves.CompleteBlock(req.SessionID); err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error completing block %v", err)
	}
	// If it is completed, set status
	if h.Carves.Completed(req.SessionID) {
		if err := h.Carves.ChangeStatus(carves.StatusCompleted, req.SessionID); err != nil {
			h.Inc(metricBlockErr)
			log.Printf("error completing carve %v", err)
		}
	} else {
		if err := h.Carves.ChangeStatus(carves.StatusInProgress, req.SessionID); err != nil {
			h.Inc(metricBlockErr)
			log.Printf("error progressing carve %v", err)
		}
	}
}
