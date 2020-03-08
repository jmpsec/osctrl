package main

import (
	"log"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/types"
)

// Function to initialize a file carve from a node
func processCarveInit(req types.CarveInitRequest, sessionid, environment string) error {
	// Retrieve node
	node, err := nodesmgr.GetByKey(req.NodeKey)
	if err != nil {
		incMetric(metricInitErr)
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
	err = filecarves.CreateCarve(carve)
	if err != nil {
		incMetric(metricInitErr)
		log.Printf("error creating  CarvedFile %v", err)
		return err
	}
	return nil
}

// Function to process one block from a file carve
// FIXME it can be more efficient on db access
func processCarveBlock(req types.CarveBlockRequest, environment string) {
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
	if err := filecarves.CreateBlock(block); err != nil {
		incMetric(metricBlockErr)
		log.Printf("error creating CarvedBlock %v", err)
	}
	// Bump block completion
	if err := filecarves.CompleteBlock(req.SessionID); err != nil {
		incMetric(metricBlockErr)
		log.Printf("error completing block %v", err)
	}
	// If it is completed, set status
	if filecarves.Completed(req.SessionID) {
		if err := filecarves.ChangeStatus(carves.StatusCompleted, req.SessionID); err != nil {
			incMetric(metricBlockErr)
			log.Printf("error completing carve %v", err)
		}
	} else {
		if err := filecarves.ChangeStatus(carves.StatusInProgress, req.SessionID); err != nil {
			incMetric(metricBlockErr)
			log.Printf("error progressing carve %v", err)
		}
	}
}
