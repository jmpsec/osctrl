package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/logsinks"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

func (h *HandlersTLS) syncCompletedCarveQuery(sessionID string) error {
	carve, err := h.Carves.GetBySession(sessionID)
	if err != nil {
		return err
	}

	query, err := h.Queries.Get(carve.QueryName, carve.EnvironmentID)
	if err != nil {
		return err
	}
	if query.Completed || query.Deleted || query.Expired {
		return nil
	}

	files, err := h.Carves.GetByQuery(carve.QueryName, carve.EnvironmentID)
	if err != nil {
		return err
	}
	if query.Expected <= 0 || len(files) < query.Expected {
		return nil
	}
	for _, file := range files {
		if file.Status != carves.StatusCompleted {
			return nil
		}
	}

	return h.Queries.Complete(carve.QueryName, carve.EnvironmentID)
}

// ProcessCarveWrite - Function to process the scheduling of file carves from a node
func (h *HandlersTLS) ProcessCarveWrite(req types.QueryCarveScheduled, queryName, nodeKey, environment string) error {
	// Retrieve node
	node, err := h.Nodes.GetByKey(nodeKey)
	if err != nil {
		log.Err(err).Msg("error retrieving node")
		return err
	}
	// Only a carve this node was asked for, in its own environment.
	assigned, err := h.Queries.HasPendingAssignment(queryName, node.ID, node.EnvironmentID)
	if err != nil {
		return err
	}
	if !assigned {
		return fmt.Errorf("node %s has no pending assignment for %s", node.UUID, queryName)
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
	// Emit carve.meta event so external sinks can track the carve lifecycle.
	h.emitCarveMetaEvent(node.EnvironmentID, environment, node.UUID, map[string]any{
		"event":       "scheduled",
		"carve_id":    req.CarveGUID,
		"request_id":  req.RequestID,
		"query_name":  queryName,
		"path":        req.Path,
		"node_uuid":   node.UUID,
		"environment": environment,
		"status":      carves.StatusScheduled,
		"carver":      h.Carves.Carver,
	})
	return nil
}

// ProcessCarveInit - Function to initialize a file carve from a node
func (h *HandlersTLS) ProcessCarveInit(req types.CarveInitRequest, sessionid, environment string, node nodes.OsqueryNode) error {
	// Create File Carve
	if err := h.Carves.InitCarve(req, sessionid, node.ID, node.EnvironmentID); err != nil {
		log.Err(err).Msg("error creating CarvedFile")
		return err
	}
	// Emit carve.meta event for the init lifecycle step.
	carve, err := h.Carves.GetBySession(sessionid)
	if err == nil {
		h.emitCarveMetaEvent(carve.EnvironmentID, environment, carve.UUID, map[string]any{
			"event":       "init",
			"carve_id":    carve.CarveID,
			"request_id":  req.RequestID,
			"session_id":  sessionid,
			"carve_size":  req.CarveSize,
			"block_count": req.BlockCount,
			"block_size":  req.BlockSize,
			"node_uuid":   carve.UUID,
			"environment": environment,
			"status":      carves.StatusInProgress,
			"carver":      h.Carves.Carver,
		})
	}
	return nil
}

// ProcessCarveBlock validates and stores one block of an in-progress carve.
func (h *HandlersTLS) ProcessCarveBlock(req types.CarveBlockRequest, carve carves.CarvedFile, environment string) error {
	if err := h.Carves.StoreBlock(carve, environment, carve.UUID, req); err != nil {
		return err
	}
	// Emit carve.data event with block metadata (not the block payload).
	h.emitCarveDataEvent(carve.EnvironmentID, environment, carve.UUID, map[string]any{
		"event":       "block",
		"session_id":  req.SessionID,
		"request_id":  req.RequestID,
		"block_id":    req.BlockID,
		"block_size":  len(req.Data),
		"node_uuid":   carve.UUID,
		"environment": environment,
		"carver":      h.Carves.Carver,
	})
	return nil
}

// finishCarveBlock updates progress after a stored block and, for the one
// worker that claims completion, finalizes the carve.
func (h *HandlersTLS) finishCarveBlock(req types.CarveBlockRequest, carve carves.CarvedFile, environment string) {
	if err := h.Carves.CompleteBlock(req.SessionID); err != nil {
		log.Err(err).Msg("error completing block")
	}
	claimed, err := h.Carves.ClaimCompletion(req.SessionID)
	if err != nil {
		log.Err(err).Msg("error completing carve")
		return
	}
	if !claimed {
		return
	}
	// Archive carve if the carver is s3. A failure leaves it unarchived;
	// the API archives on download.
	if h.Carves.Carver == config.CarverS3 {
		if archived, err := h.Carves.Archive(req.SessionID, ""); err != nil {
			log.Err(err).Msg("error archiving results")
		} else if archived == nil {
			log.Error().Msg("empty archive")
		} else if err := h.Carves.ArchiveCarve(req.SessionID, archived.File); err != nil {
			log.Err(err).Msg("error archiving carve")
		}
	}
	if err := h.syncCompletedCarveQuery(req.SessionID); err != nil {
		log.Err(err).Msg("error syncing completed carve query")
	}
	h.emitCarveMetaEvent(carve.EnvironmentID, environment, carve.UUID, map[string]any{
		"event":            "completed",
		"carve_id":         carve.CarveID,
		"request_id":       req.RequestID,
		"session_id":       req.SessionID,
		"node_uuid":        carve.UUID,
		"environment":      environment,
		"status":           carves.StatusCompleted,
		"carver":           h.Carves.Carver,
		"total_blocks":     carve.TotalBlocks,
		"completed_blocks": carve.TotalBlocks,
		"carve_size":       carve.CarveSize,
	})
}

// emitCarveMetaEvent dispatches a carve.meta lifecycle event through the
// log sink fan-out. Sinks configured with the "carve.meta" category
// (or "all") will receive it.
func (h *HandlersTLS) emitCarveMetaEvent(envID uint, environment, uuid string, payload map[string]any) {
	if h.Logs == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("error marshaling carve.meta event")
		return
	}
	h.Logs.LogWithEnv(logsinks.CatCarveMeta, data, envID, environment, uuid, false)
}

// emitCarveDataEvent dispatches a carve.data block event through the
// log sink fan-out. Sinks configured with the "carve.data" category
// (or "all") will receive it. The event carries block metadata only,
// not the raw block payload — that is stored by pkg/carves.
func (h *HandlersTLS) emitCarveDataEvent(envID uint, environment, uuid string, payload map[string]any) {
	if h.Logs == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("error marshaling carve.data event")
		return
	}
	h.Logs.LogWithEnv(logsinks.CatCarveData, data, envID, environment, uuid, false)
}
