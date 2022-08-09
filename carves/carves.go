package carves

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/settings"
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

// CarveType as abstraction of storage type for the carver
type CarverType int

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

// CarveResult holds metadata related to a carve
type CarveResult struct {
	Size int64
	File string
}

// Carves to handle file carves from nodes
type Carves struct {
	DB     *gorm.DB
	S3     *CarverS3
	Carver string
}

// CreateFileCarves to initialize the carves struct and tables
func CreateFileCarves(backend *gorm.DB, carverType string, s3 *CarverS3) *Carves {
	var c *Carves
	c = &Carves{DB: backend, Carver: carverType, S3: s3}
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
			"carver":       c.Carver,
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

// InitateBlock to initiate a block based on the configured carver
func (c *Carves) InitateBlock(env, uuid, requestid, sessionid, data string, blockid int) CarvedBlock {
	res := CarvedBlock{
		RequestID:   requestid,
		SessionID:   sessionid,
		Environment: env,
		BlockID:     blockid,
		Size:        len(data),
		Data:        GenerateS3Data(c.S3.Configuration.Bucket, env, uuid, sessionid, blockid),
		Carver:      c.Carver,
	}
	if c.Carver != settings.CarverS3 {
		res.Data = data
	}
	return res
}

// CreateBlock to create a new block for a carve
func (c *Carves) CreateBlock(block CarvedBlock, uuid, data string) error {
	switch c.Carver {
	case settings.CarverDB:
		return c.DB.Create(&block).Error // can be nil or err
	case settings.CarverS3:
		if c.S3 != nil {
			return c.S3.Upload(block, uuid, data)
		}
		return fmt.Errorf("S3 carver not initialized")
	}
	return fmt.Errorf("Unknown carver") // can be nil or err
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

// GetBySession to get a carve by session_id
func (c *Carves) GetBySession(sessionid string) (CarvedFile, error) {
	var carve CarvedFile
	if err := c.DB.Where("session_id = ?", sessionid).Find(&carve).Error; err != nil {
		return carve, err
	}
	return carve, nil
}

// GetByRequest to get a carve by request_id
func (c *Carves) GetByRequest(requestid string) ([]CarvedFile, error) {
	var carves []CarvedFile
	if err := c.DB.Where("request_id = ?", requestid).Find(&carves).Error; err != nil {
		return carves, err
	}
	return carves, nil
}

// GetBlocks to get a carve by session_id and ordered by block_id
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

// ArchiveCarve to mark one carve as archived and set the received file
func (c *Carves) ArchiveCarve(sessionid, archive string) error {
	carve, err := c.GetBySession(sessionid)
	if err != nil {
		return fmt.Errorf("getCarveBySessionID %v", err)
	}
	toUpdate := map[string]interface{}{
		"archived":      true,
		"archived_path": archive,
	}
	if err := c.DB.Model(&carve).Updates(toUpdate).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
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
func (c *Carves) Archive(sessionid, destPath string) (*CarveResult, error) {
	// Get carve
	carve, err := c.GetBySession(sessionid)
	if err != nil {
		return nil, fmt.Errorf("error getting carve - %v", err)
	}
	if carve.Archived {
		return &CarveResult{
			Size: int64(carve.CarveSize),
			File: carve.ArchivePath,
		}, nil
	}
	// Get all blocks
	blocks, err := c.GetBlocks(carve.SessionID)
	if err != nil {
		return nil, fmt.Errorf("error getting blocks - %v", err)
	}
	switch c.Carver {
	case settings.CarverLocal:
		return c.ArchiveLocal(destPath, carve, blocks)
	case settings.CarverDB:
		return c.ArchiveLocal(destPath, carve, blocks)
	case settings.CarverS3:
		return c.S3.Archive(carve, blocks)
	}
	return nil, fmt.Errorf("unknown carver - %s", c.Carver)
}

// Archive to convert finalize a completed carve and create a file ready to download
func (c *Carves) ArchiveLocal(destPath string, carve CarvedFile, blocks []CarvedBlock) (*CarveResult, error) {
	res := &CarveResult{
		File: destPath,
	}
	// Make sure last character is a slash
	if destPath[len(destPath)-1:] != "/" {
		res.File += "/"
	}
	res.File += GenerateArchiveName(carve)
	// If file already exists, no need to re-generate it from blocks
	_f, err := os.Stat(res.File)
	if err == nil {
		res.Size = _f.Size()
		return res, nil
	}
	// Also check for compressed
	_f, err = os.Stat(res.File + ZstFileExtension)
	if err == nil {
		res.Size = _f.Size()
		return res, nil
	}
	// Check if data is compressed
	zstd, err := CheckCompressionBlock(blocks[0])
	if err != nil {
		return res, fmt.Errorf("Compression check - %v", err)
	}
	if zstd {
		res.File += ZstFileExtension
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
