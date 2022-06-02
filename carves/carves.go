package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/types"
	"gorm.io/gorm"
)

// Support for undocumented file carving API
// https://github.com/mwielgoszewski/doorman/issues/120

const (
	// StatusQueried for queried carves that did not hit nodes yet
	StatusQueried string = "QUERIED"
	// StatusScheduled for initialized carves
	StatusScheduled string = "SCHEDULED"
	// StatusInProgress for carves that are on-going
	StatusInProgress string = "IN PROGRESS"
	// StatusCompleted for carves that finalized
	StatusCompleted string = "COMPLETED"
	// TarFileExtension to identify Tar files extension
	TarFileExtension string = ".tar"
	// ZstFileExtension to identify ZST compressed files
	ZstFileExtension string = ".zst"
)

var (
	// CompressionHeader to detect the usage of compressed carves (zstd header)
	// https://github.com/facebook/zstd
	CompressionHeader = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// MappedCarves to pass carves by query name / Request ID
type MappedCarves map[string][]CarvedFile

// QueriedCarve to be used to display the carves in a table
type QueriedCarve struct {
	Name    string
	Path    string
	Status  string
	Creator string
}

// CarvedFile to keep track of carved files from nodes
type CarvedFile struct {
	gorm.Model
	CarveID         string `gorm:"unique;index"`
	RequestID       string
	SessionID       string
	QueryName       string
	UUID            string `gorm:"index"`
	Environment     string
	Path            string
	CarveSize       int
	BlockSize       int
	TotalBlocks     int
	CompletedBlocks int
	Status          string
	CompletedAt     time.Time
}

// CarvedBlock to store each block from a carve
type CarvedBlock struct {
	gorm.Model
	RequestID   string `gorm:"index"`
	SessionID   string `gorm:"index"`
	Environment string
	BlockID     int
	Data        string
	Size        int
}

// CarveResult holds metadata related to a carve
type CarveResult struct {
	Size int64
	File string
}

// Carves to handle file carves from nodes
type Carves struct {
	DB *gorm.DB
}

// CreateFileCarves to initialize the carves struct and tables
func CreateFileCarves(backend *gorm.DB) *Carves {
	var c *Carves
	c = &Carves{DB: backend}
	// table carved_files
	if err := backend.AutoMigrate(&CarvedFile{}); err != nil {
		log.Fatalf("Failed to AutoMigrate table (carved_files): %v", err)
	}
	// table carved_blocks
	if err := backend.AutoMigrate(&CarvedBlock{}); err != nil {
		log.Fatalf("Failed to AutoMigrate table (carved_blocks): %v", err)
	}
	return c
}

// CreateCarve to create a new carved file for a node
func (c *Carves) CreateCarve(carve CarvedFile) error {
	return c.DB.Create(&carve).Error // can be nil or err
}

// InitCarve to initialize an scheduled carve
func (c *Carves) InitCarve(req types.CarveInitRequest, sessionid string) error {
	carves, err := c.GetByRequest(req.RequestID)
	if err != nil {
		return fmt.Errorf("getCarveByRequest %v", err)
	}
	for _, carve := range carves {
		toUpdate := map[string]interface{}{
			"carve_size":   req.CarveSize,
			"total_blocks": req.BlockCount,
			"block_size":   req.BlockSize,
			"session_id":   sessionid,
			"status":       StatusInProgress,
		}
		if err := c.DB.Model(&carve).Updates(toUpdate).Error; err != nil {
			return err
		}
	}
	return nil
}

// CheckCarve to verify a session belong to a carve
func (c *Carves) CheckCarve(sessionid, requestid string) bool {
	carve, err := c.GetBySession(sessionid)
	if err != nil {
		return false
	}
	return (carve.RequestID == strings.TrimSpace(requestid))
}

// GetCarve to verify a session belong to a carve
func (c *Carves) GetCheckCarve(sessionid, requestid string) (CarvedFile, error) {
	carve, err := c.GetBySession(sessionid)
	if err != nil {
		return carve, fmt.Errorf("GetBySession %v", err)
	}
	if carve.RequestID != strings.TrimSpace(requestid) {
		return CarvedFile{}, fmt.Errorf("RequestID does not match carve %s != %s", carve.RequestID, requestid)
	}
	return carve, nil
}

// CreateBlock to create a new block for a carve
func (c *Carves) CreateBlock(block CarvedBlock) error {
	return c.DB.Create(&block).Error // can be nil or err
}

// Delete to delete a carve by id
func (c *Carves) Delete(carveid string) error {
	carve, err := c.GetByCarve(carveid)
	if err != nil {
		return fmt.Errorf("getCarveByID %v", err)
	}
	if err := c.DB.Unscoped().Delete(&carve).Error; err != nil {
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
		if err := c.DB.Unscoped().Delete(&b).Error; err != nil {
			return fmt.Errorf("Delete %v", err)
		}
	}
	return nil
}

// GetByCarve to get a carve by carve id
func (c *Carves) GetByCarve(carveid string) (CarvedFile, error) {
	var carve CarvedFile
	if err := c.DB.Where("carve_id = ?", carveid).Find(&carve).Error; err != nil {
		return carve, err
	}
	return carve, nil
}

// GetBySession to get a carve by session id
func (c *Carves) GetBySession(sessionid string) (CarvedFile, error) {
	var carve CarvedFile
	if err := c.DB.Where("session_id = ?", sessionid).Find(&carve).Error; err != nil {
		return carve, err
	}
	return carve, nil
}

// GetByRequest to get a carve by request id
func (c *Carves) GetByRequest(requestid string) ([]CarvedFile, error) {
	var carves []CarvedFile
	if err := c.DB.Where("request_id = ?", requestid).Find(&carves).Error; err != nil {
		return carves, err
	}
	return carves, nil
}

// GetBlocks to get a carve by session id
func (c *Carves) GetBlocks(sessionid string) ([]CarvedBlock, error) {
	var blocks []CarvedBlock
	if err := c.DB.Where("session_id = ?", sessionid).Order("block_id").Find(&blocks).Error; err != nil {
		return blocks, err
	}
	return blocks, nil
}

// GetByQuery to get a carve by query name
func (c *Carves) GetByQuery(name string) ([]CarvedFile, error) {
	var carves []CarvedFile
	if err := c.DB.Where("query_name = ?", name).Find(&carves).Error; err != nil {
		return carves, err
	}
	return carves, nil
}

// CheckCompression to verify if the blocks are compressed using zstd
func (c *Carves) CheckCompression(block CarvedBlock) (bool, error) {
	// Make sure this is the block 0
	if block.BlockID != 0 {
		return false, fmt.Errorf("block_id is not 0 (%d)", block.BlockID)
	}
	compressionCheck, err := base64.StdEncoding.DecodeString(block.Data)
	if err != nil {
		return false, fmt.Errorf("Decoding first block %v", err)
	}
	if bytes.Compare(compressionCheck[:4], CompressionHeader) == 0 {
		return true, nil
	}
	return false, nil
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
	carve, err := c.GetBySession(sessionid)
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
	carve, err := c.GetBySession(sessionid)
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
	carve, err := c.GetBySession(sessionid)
	if err != nil {
		return false
	}
	return (carve.TotalBlocks == carve.CompletedBlocks)
}

// Archive to convert finalize a completed carve and create a file ready to download
func (c *Carves) Archive(sessionid, path string) (*CarveResult, error) {
	res := &CarveResult{
		File: path,
	}
	// Make sure last character is a slash
	if path[len(path)-1:] != "/" {
		res.File += "/"
	}
	res.File += sessionid + TarFileExtension
	// If file already exists, no need to re-generate it from blocks
	_f, err := os.Stat(res.File)
	if err == nil {
		res.Size = _f.Size()
		return res, nil
	}
	_f, err = os.Stat(res.File + ZstFileExtension)
	if err == nil {
		res.Size = _f.Size()
		return res, nil
	}
	// Get all blocks
	blocks, err := c.GetBlocks(sessionid)
	if err != nil {
		return res, fmt.Errorf("Getting blocks - %v", err)
	}
	zstd, err := c.CheckCompression(blocks[0])
	if err != nil {
		return res, fmt.Errorf("Compression check - %v", err)
	}
	if zstd {
		res.File += ".zst"
	}
	f, err := os.OpenFile(res.File, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return res, fmt.Errorf("File creation - %v", err)
	}
	defer f.Close()
	// Iterate through blocks and write decoded content to file
	for _, b := range blocks {
		toFile, err := base64.StdEncoding.DecodeString(b.Data)
		if err != nil {
			return res, fmt.Errorf("Decoding data - %v", err)
		}
		if _, err := f.Write(toFile); err != nil {
			return res, fmt.Errorf("Writing to file - %v", err)
		}
		res.Size += int64(len(toFile))
	}
	return res, nil
}
