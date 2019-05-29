package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

const (
	// StatusInitialized for initialized carves
	StatusInitialized string = "INITIALIZED"
	// StatusInProgress for carves that are on-going
	StatusInProgress string = "IN PROGRESS"
	// StatusCompleted for carves that finalized
	StatusCompleted string = "COMPLETED"
	// StatusArchived for carves ready to be downloaded
	StatusArchived string = "ARCHIVED"
)

var (
	// CompressionHeader to detect the usage of compressed carves (zstd header)
	CompressionHeader = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// CarvedFile to keep track of carved files from nodes
type CarvedFile struct {
	gorm.Model
	CarveID         string `gorm:"unique;index"`
	RequestID       string
	SessionID       string
	UUID            string `gorm:"index"`
	Context         string
	CarveSize       int
	BlockSize       int
	TotalBlocks     int
	CompletedBlocks int
	CarvedPath      string
	DestPath        string
	Status          string
	CompletedAt     time.Time
}

// CarvedBlock to store each block from a carve
type CarvedBlock struct {
	gorm.Model
	RequestID string `gorm:"index"`
	SessionID string `gorm:"index"`
	Context   string
	BlockID   int
	Data      string
}

// Carves to handle file carves from nodes
type Carves struct {
	DB *gorm.DB
}

// CreateFileCarves to initialize the carves struct
func CreateFileCarves(backend *gorm.DB) *Carves {
	var c *Carves
	c = &Carves{DB: backend}
	return c
}

// CreateCarve to create a new carved file for a node
func (c *Carves) CreateCarve(carve CarvedFile) error {
	if c.DB.NewRecord(carve) {
		if err := c.DB.Create(&carve).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// CheckCarve to verify a session belong to a carve
func (c *Carves) CheckCarve(sessionid, requestid string) bool {
	carve, err := c.GetCarveBySession(sessionid)
	if err != nil {
		return false
	}
	return (carve.RequestID == strings.TrimSpace(requestid))
}

// CreateBlock to create a new block for a carve
func (c *Carves) CreateBlock(block CarvedBlock) error {
	if c.DB.NewRecord(block) {
		if err := c.DB.Create(&block).Error; err != nil {
			return err
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// DeleteCarve to delete a carve by id
func (c *Carves) DeleteCarve(carveid string) error {
	carve, err := c.GetCarve(carveid)
	if err != nil {
		return fmt.Errorf("getCarveByID %v", err)
	}
	if err := c.DB.Delete(&carve).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// DeleteBlocks to delete all blocks by session id
func (c *Carves) DeleteBlocks(sessionid string) error {
	blocks, err := c.GetBlocks(sessionid)
	if err != nil {
		return fmt.Errorf("getBlocksBySessionID %v", err)
	}
	for _, b := range blocks {
		if err := c.DB.Delete(&b).Error; err != nil {
			return fmt.Errorf("Delete %v", err)
		}
	}
	return nil
}

// GetCarve to get a carve by carve id
func (c *Carves) GetCarve(carveid string) (CarvedFile, error) {
	var carve CarvedFile
	if err := c.DB.Where("carve_id = ?", carveid).Find(&carve).Error; err != nil {
		return carve, err
	}
	return carve, nil
}

// GetCarveBySession to get a carve by session id
func (c *Carves) GetCarveBySession(sessionid string) (CarvedFile, error) {
	var carve CarvedFile
	if err := c.DB.Where("session_id = ?", sessionid).Find(&carve).Error; err != nil {
		return carve, err
	}
	return carve, nil
}

// GetBlocks to get a carve by session id
func (c *Carves) GetBlocks(sessionid string) ([]CarvedBlock, error) {
	var blocks []CarvedBlock
	if err := c.DB.Where("session_id = ?", sessionid).Order("block_id").Find(&blocks).Error; err != nil {
		return blocks, err
	}
	return blocks, nil
}

// GetNodeCarves to get all the carves for a given node
func (c *Carves) GetNodeCarves(uuid string) ([]CarvedFile, error) {
	var carves []CarvedFile
	if err := c.DB.Where("uuid = ?", uuid).Find(&carves).Error; err != nil {
		return carves, err
	}
	return carves, nil
}

// ChangeStatus to change the status of a carve
func (c *Carves) ChangeStatus(status, sessionid string) error {
	carve, err := c.GetCarveBySession(sessionid)
	if err != nil {
		return fmt.Errorf("getCarveBySessionID %v", err)
	}
	if err := c.DB.Model(&carve).Update("status", status).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	if status == StatusCompleted {
		if err := c.DB.Model(&carve).Update("completed_at", time.Now()).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	return nil
}

// CompleteBlock to increase one block for a carve
func (c *Carves) CompleteBlock(sessionid string) error {
	carve, err := c.GetCarveBySession(sessionid)
	if err != nil {
		return fmt.Errorf("getCarveBySessionID %v", err)
	}
	if err := c.DB.Model(&carve).Update("completed_blocks", carve.CompletedBlocks+1).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// Completed to check if a carve is completed
// FIXME return error maybe?
func (c *Carves) Completed(sessionid string) bool {
	carve, err := c.GetCarveBySession(sessionid)
	if err != nil {
		return false
	}
	return (carve.TotalBlocks == carve.CompletedBlocks)
}

// Archive to convert finalize a completed carve and create a file ready to download
func (c *Carves) Archive(sessionid, path string) error {
	encodedFile := path + "/" + sessionid + ".b64"
	finalExtension := ".tar"
	finalFile := path + "/" + sessionid
	// Prepare file for the encoded content
	encF, err := os.OpenFile(encodedFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("Opening encoded file %v", err)
	}
	// Get all blocks
	blocks, err := c.GetBlocks(sessionid)
	if err != nil {
		return fmt.Errorf("Getting blocks %v", err)
	}
	// Iterate through blocks and write encoded content to file
	// Check the first block, to see if the carve was compressed
	for _, b := range blocks {
		if b.BlockID == 0 {
			compressionCheck, err := base64.StdEncoding.DecodeString(b.Data)
			if err != nil {
				return fmt.Errorf("Decoding first block %v", err)
			}
			if bytes.Compare(compressionCheck[:4], CompressionHeader) == 0 {
				finalExtension += ".zst"
			}
		}
		if _, err = encF.WriteString(b.Data); err != nil {
			return fmt.Errorf("Writing encoded file %v", err)
		}
	}
	// Close encoded file
	if err := encF.Close(); err != nil {
		return fmt.Errorf("Closing encoded file %v", err)
	}
	// Open encoded file again
	encodedData, err := os.Open(encodedFile)
	if err != nil {
		return fmt.Errorf("Opening encoded data %v", err)
	}
	defer encodedData.Close()
	// Prepare file to store the decoded data
	decodedFile, err := os.Create(finalFile + finalExtension)
	if err != nil {
		return fmt.Errorf("Opening decoded file %v", err)
	}
	// Close output file
	defer decodedFile.Close()
	// Decode the base64 encoded
	decoder := base64.NewDecoder(base64.StdEncoding, encodedData)
	// Copy from base64 decoder to final file
	_, err = io.Copy(decodedFile, decoder)
	if err != nil {
		return fmt.Errorf("Saving decoded data %v", err)
	}
	return nil
}
