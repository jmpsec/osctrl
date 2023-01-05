package metrics

import (
	"fmt"
	"log"

	"github.com/jmpsec/osctrl/types"
	"gorm.io/gorm"
)

// IngestedDataType to define the types of ingested data
type IngestedDataType uint8

const (
	// IngestedStatus for status logs
	IngestedStatus IngestedDataType = iota
	// IngestedResult for result logs
	IngestedResult
	// IngestedQueryRead for on-demand query requests
	IngestedQueryRead
	// IngestedQueryWrite for on-demand query results
	IngestedQueryWrite
	// IngestedConfig for configuration requests
	IngestedConfig
	// IngestedCarveInit for initialization of carves
	IngestedCarveInit
	// IngestedCarveBlock for carve blocks
	IngestedCarveBlock
)

// IngestedData as abstraction of ingested data
type IngestedData struct {
	gorm.Model
	EnvironmentID uint
	BytesIngested int
	NodeID        uint
	DataType      uint8
}

// IngestedManager to store and get ingested data
type IngestedManager struct {
	DB *gorm.DB
}

// CreateIngested to initialize the ingested struct and its tables
func CreateIngested(backend *gorm.DB) *IngestedManager {
	var i *IngestedManager
	i = &IngestedManager{DB: backend}
	// table ingested_data
	if err := backend.AutoMigrate(&IngestedData{}); err != nil {
		log.Fatalf("Failed to AutoMigrate table (ingested_data): %v", err)
	}
	return i
}

// Create to insert new ingested data
func (i *IngestedManager) Create(data *IngestedData) error {
	if err := i.DB.Create(&data).Error; err != nil {
		return fmt.Errorf("Create %v", err)
	}
	return nil
}

// IngestGeneric to insert generic ingested data
func (i *IngestedManager) IngestGeneric(env, node uint, bIngested int, ingestedType uint8) error {
	d := IngestedData{
		EnvironmentID: env,
		BytesIngested: bIngested,
		NodeID:        node,
		DataType:      ingestedType,
	}
	return i.Create(&d)
}

// IngestLog to insert ingested new logs data
func (i *IngestedManager) IngestLog(env, node uint, bIngested int, logType string) error {
	switch logType {
	case types.ResultLog:
		return i.IngestGeneric(env, node, bIngested, uint8(IngestedResult))
	case types.StatusLog:
		return i.IngestGeneric(env, node, bIngested, uint8(IngestedStatus))
	}
	return fmt.Errorf("invalid log type %s", logType)
}

// IngestStatus to insert ingested new status logs data
func (i *IngestedManager) IngestStatus(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedStatus))
}

// IngestResult to insert ingested new result logs data
func (i *IngestedManager) IngestResult(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedResult))
}

// IngestQueryRead to insert ingested on-demand query requests
func (i *IngestedManager) IngestQueryRead(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedQueryRead))
}

// IngestQueryWrite to insert ingested on-demand query results
func (i *IngestedManager) IngestQueryWrite(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedQueryWrite))
}

// IngestConfig to insert ingested configuration requests
func (i *IngestedManager) IngestConfig(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedConfig))
}

// IngestCarveInit to insert ingested initialization carve requests
func (i *IngestedManager) IngestCarveInit(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedCarveInit))
}

// IngestCarveBlock to insert ingested block carve requests
func (i *IngestedManager) IngestCarveBlock(env, node uint, bIngested int) error {
	return i.IngestGeneric(env, node, bIngested, uint8(IngestedCarveBlock))
}
