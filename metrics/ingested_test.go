package metrics

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmpsec/osctrl/types"
	"github.com/test-go/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestIngested(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("failed to open mock sql db, got error: %v", err)
	}
	defer mockDB.Close()
	if mockDB == nil {
		t.Error("mock db is null")
	}
	if mock == nil {
		t.Error("sqlmock is null")
	}
	_postgres, err := gorm.Open(postgres.New(postgres.Config{Conn: mockDB}), &gorm.Config{})
	if err != nil {
		t.Errorf("unable to create new postgres database: %v", err)
	}
	var manager *IngestedManager
	t.Run("CreateIngestedManager", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).WithArgs("ingested_data", "BASE TABLE").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}), sqlmock.NewRows([]string{"RowsAffected"}).AddRow(1).AddRow(1))
		mock.ExpectExec(`CREATE TABLE "ingested_data" .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))

		manager = CreateIngested(_postgres)

		assert.NotEqual(t, nil, manager)
	})
	t.Run("CreateIngestedData", func(t *testing.T) {
		tt := time.Now()
		data := &IngestedData{
			EnvironmentID: 111,
			BytesIngested: 12345,
			NodeID:        222,
			DataType:      0,
		}
		data.CreatedAt = tt
		data.UpdatedAt = tt

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(tt, tt, nil, data.EnvironmentID, data.BytesIngested, data.NodeID, data.DataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.Create(data)

		assert.NoError(t, err)

		assert.Equal(t, 12345, data.BytesIngested)
		assert.Equal(t, uint(222), data.NodeID)
		assert.Equal(t, 111, int(data.EnvironmentID))
		assert.Equal(t, uint8(0), data.DataType)
	})
	t.Run("CreateIngestGeneric", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(0)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestGeneric(envID, nodeID, bytesIngested, dataType)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(0), dataType)
	})
	t.Run("CreateIngestLog", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(1)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestLog(envID, nodeID, bytesIngested, types.ResultLog)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(1), dataType)
	})
	t.Run("CreateIngestStatus", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(0)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestStatus(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(0), dataType)
	})
	t.Run("CreateIngestResult", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(1)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestResult(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(1), dataType)
	})
	t.Run("CreateIngestQueryRead", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(2)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestQueryRead(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(2), dataType)
	})
	t.Run("CreateIngestQueryWrite", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(3)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestQueryWrite(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(3), dataType)
	})
	t.Run("CreateIngestConfig", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(4)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestConfig(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(4), dataType)
	})
	t.Run("CreateIngestCarveInit", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(5)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestCarveInit(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(5), dataType)
	})
	t.Run("CreateIngestCarveBlock", func(t *testing.T) {
		envID := uint(111)
		bytesIngested := 12345
		nodeID := uint(222)
		dataType := uint8(6)

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "ingested_data" ("created_at","updated_at","deleted_at","environment_id","bytes_ingested","node_id","data_type") VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "id"`)).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, envID, bytesIngested, nodeID, dataType).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.IngestCarveBlock(envID, nodeID, bytesIngested)

		assert.NoError(t, err)

		assert.Equal(t, 12345, bytesIngested)
		assert.Equal(t, uint(222), nodeID)
		assert.Equal(t, 111, int(envID))
		assert.Equal(t, uint8(6), dataType)
	})
}
