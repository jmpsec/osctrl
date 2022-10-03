package handlers

import (
	"log"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

// ProcessCarveWrite - Function to process the scheduling of file carves from a node
func (h *HandlersTLS) ProcessCarveWrite(req types.QueryCarveScheduled, queryName, nodeKey, environment string) error {
	// Retrieve node
	node, err := h.Nodes.GetByKey(nodeKey)
	if err != nil {
		h.Inc(metricInitErr)
		log.Printf("error retrieving node %s", err)
		return err
	}
	// Prepare carve to be scheduled
	carve := carves.CarvedFile{
		CarveID:         req.CarveGUID,
		RequestID:       req.RequestID,
		UUID:            node.UUID,
		Environment:     environment,
		Path:            req.Path,
		QueryName:       queryName,
		CarveSize:       0,
		BlockSize:       0,
		TotalBlocks:     0,
		CompletedBlocks: 0,
		Status:          carves.StatusScheduled,
		Carver:          h.Carves.Carver,
		Archived:        false,
		ArchivePath:     "",
		EnvironmentID:   node.EnvironmentID,
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

// ProcessCarveInit - Function to initialize a file carve from a node
func (h *HandlersTLS) ProcessCarveInit(req types.CarveInitRequest, sessionid, environment string) error {
	// Create File Carve
	if err := h.Carves.InitCarve(req, sessionid); err != nil {
		h.Inc(metricInitErr)
		log.Printf("error creating CarvedFile %v", err)
		return err
	}
	return nil
}

// ProcessCarveBlock - Function to process one block from a file carve
// FIXME it can be more efficient on db access
func (h *HandlersTLS) ProcessCarveBlock(req types.CarveBlockRequest, environment, uuid string, envid uint) {
	// Initiate carve block
	block := h.Carves.InitateBlock(environment, uuid, req.RequestID, req.SessionID, req.Data, req.BlockID, envid)
	// Create Block
	if err := h.Carves.CreateBlock(block, uuid, req.Data); err != nil {
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
		// Archive carve if the carver is s3
		if h.Carves.Carver == settings.CarverS3 {
			archived, err := h.Carves.Archive(req.SessionID, "")
			if err != nil {
				h.Inc(metricBlockErr)
				log.Printf("error archiving results %v", err)
				return
			}
			if archived == nil {
				h.Inc(metricBlockErr)
				log.Printf("empty archive %v", err)
				return
			}
			if err := h.Carves.ArchiveCarve(req.SessionID, archived.File); err != nil {
				h.Inc(metricBlockErr)
				log.Printf("error archiving carve %v", err)
			}
		}
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
