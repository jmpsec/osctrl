package handlers

import (
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// ProcessCarveWrite - Function to process the scheduling of file carves from a node
func (h *HandlersTLS) ProcessCarveWrite(req types.QueryCarveScheduled, queryName, nodeKey, environment string) error {
	// Retrieve node
	node, err := h.Nodes.GetByKey(nodeKey)
	if err != nil {
		log.Err(err).Msg("error retrieving node")
		return err
	}
	// Prepare carve to be scheduled
	carve := carves.CarvedFile{
		CarveID:         req.CarveGUID,
		RequestID:       req.RequestID,
		UUID:            node.UUID,
		NodeID:          node.ID,
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
		log.Err(err).Msg("error creating CarvedFile")
		return err
	}
	return nil
}

// ProcessCarveInit - Function to initialize a file carve from a node
func (h *HandlersTLS) ProcessCarveInit(req types.CarveInitRequest, sessionid, environment string) error {
	// Create File Carve
	if err := h.Carves.InitCarve(req, sessionid); err != nil {
		log.Err(err).Msg("error creating CarvedFile")
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
		log.Err(err).Msg("error creating CarvedBlock")
	}
	// Bump block completion
	if err := h.Carves.CompleteBlock(req.SessionID); err != nil {
		log.Err(err).Msg("error completing block")
	}
	// If it is completed, set status
	if h.Carves.Completed(req.SessionID) {
		// Archive carve if the carver is s3
		if h.Carves.Carver == config.CarverS3 {
			archived, err := h.Carves.Archive(req.SessionID, "")
			if err != nil {
				log.Err(err).Msg("error archiving results")
				return
			}
			if archived == nil {
				log.Error().Msg("empty archive")
				return
			}
			if err := h.Carves.ArchiveCarve(req.SessionID, archived.File); err != nil {
				log.Err(err).Msg("error archiving carve")
			}
		}
		if err := h.Carves.ChangeStatus(carves.StatusCompleted, req.SessionID); err != nil {
			log.Err(err).Msg("error completing carve")
		}
	} else {
		if err := h.Carves.ChangeStatus(carves.StatusInProgress, req.SessionID); err != nil {
			log.Err(err).Msg("error progressing carve")
		}
	}
}
