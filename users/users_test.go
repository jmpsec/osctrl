package users

import (
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmpsec/osctrl/types"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
)

func TestCreateUserManager(t *testing.T) {
	conf := types.JSONConfigurationJWT{
		JWTSecret:     "test",
		HoursToExpire: 1,
	}
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
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).WithArgs("admin_users", "BASE TABLE").WillReturnRows(sqlmock.NewRows([]string{"LastInsertId"}), sqlmock.NewRows([]string{"RowsAffected"}).AddRow(1).AddRow(1))
	mock.ExpectExec(`CREATE TABLE "admin_users" .*`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).WithArgs("user_permissions", "BASE TABLE").WillReturnRows(sqlmock.NewRows([]string{"LastInsertId"}), sqlmock.NewRows([]string{"RowsAffected"}).AddRow(1).AddRow(1))
	mock.ExpectExec(`CREATE TABLE "user_permissions" .*`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))

	manager := CreateUserManager(_postgres, &conf)

	assert.NotEqual(t, nil, manager)
}
