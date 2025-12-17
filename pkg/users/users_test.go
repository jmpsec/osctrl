package users

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmpsec/osctrl/pkg/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
)

func setupTestManager(t *testing.T) (*UserManager, sqlmock.Sqlmock) {
	conf := config.YAMLConfigurationJWT{
		JWTSecret:     "test",
		HoursToExpire: 1,
	}
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("failed to open mock sql db, got error: %v", err)
	}
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

	// Set up mock expectations for AutoMigrate before creating the manager
	// admin_users table
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).
		WithArgs("admin_users", "BASE TABLE").
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(0))
	mock.ExpectExec(`CREATE TABLE "admin_users" .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// user_permissions table
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).
		WithArgs("user_permissions", "BASE TABLE").
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(0))
	mock.ExpectExec(`CREATE TABLE "user_permissions" .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	manager := CreateUserManager(_postgres, &conf)
	return manager, mock
}

func TestCreateUserManager(t *testing.T) {
	manager, _ := setupTestManager(t)
	assert.NotEqual(t, nil, manager)
}

func TestHashTextWithSalt(t *testing.T) {
	manager, _ := setupTestManager(t)
	hashed, err := manager.HashTextWithSalt("testText")
	assert.NoError(t, err)
	assert.Equal(t, hashed[0:7], "$2a$10$")
}

func TestHashPasswordWithSalt(t *testing.T) {
	manager, _ := setupTestManager(t)
	hashed, err := manager.HashPasswordWithSalt("testPassword")
	assert.NoError(t, err)
	assert.Equal(t, hashed[0:7], "$2a$10$")
}

func TestCheckLoginCredentials(t *testing.T) {
	manager, mock := setupTestManager(t)
	hashed, err := manager.HashPasswordWithSalt("testPassword")
	assert.NoError(t, err)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "username", "pass_hash", "admin", "environment_id", "service"}).
			AddRow("aa@bb.com", "testUser", hashed, true, 123, false))

	access, user := manager.CheckLoginCredentials("testUser", "testPassword")

	assert.Equal(t, true, access)
	assert.Equal(t, "aa@bb.com", user.Email)
	assert.Equal(t, "testUser", user.Username)
	assert.Equal(t, true, user.Admin)
	assert.Equal(t, 123, int(user.EnvironmentID))
	assert.Equal(t, false, user.Service)
}

func TestCreateCheckToken(t *testing.T) {
	manager, _ := setupTestManager(t)
	conf := config.YAMLConfigurationJWT{
		JWTSecret: "test",
	}
	token, tt, err := manager.CreateToken("testUsername", "issuer", 0)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	now := time.Now()
	assert.Equal(t, true, tt.After(now))
	claims, valid := manager.CheckToken(conf.JWTSecret, token)
	assert.Equal(t, true, valid)
	assert.Equal(t, "testUsername", claims.Username)
}

func TestGetUser(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "username", "admin", "environment_id"}).
			AddRow("aa@bb.com", "testUser", true, 123))

	user, err := manager.Get("testUser")
	assert.NoError(t, err)

	assert.Equal(t, "aa@bb.com", user.Email)
	assert.Equal(t, "testUser", user.Username)
	assert.Equal(t, true, user.Admin)
	assert.Equal(t, 123, int(user.EnvironmentID))
}

func TestCreateUser(t *testing.T) {
	manager, mock := setupTestManager(t)
	tt := time.Now()
	user := AdminUser{
		Username:      "testUser",
		Email:         "aa@bb.com",
		Admin:         true,
		EnvironmentID: 111,
	}
	user.CreatedAt = tt
	user.UpdatedAt = tt
	user.TokenExpire = tt
	user.LastTokenUse = tt
	user.LastAccess = tt

	mock.ExpectBegin()
	mock.ExpectQuery(
		regexp.QuoteMeta(`INSERT INTO "admin_users" ("created_at","updated_at","deleted_at","username","email","fullname","pass_hash","api_token","token_expire","admin","service","uuid","csrf_token","last_ip_address","last_user_agent","last_access","last_token_use","environment_id") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING "id"`)).
		WithArgs(tt, tt, nil, user.Username, user.Email, user.Fullname, user.PassHash, user.APIToken, tt, user.Admin, user.Service, user.UUID, user.CSRFToken, user.LastIPAddress, user.LastUserAgent, tt, tt, user.EnvironmentID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
	mock.ExpectCommit()
	err := manager.Create(user)

	assert.NoError(t, err)

	assert.Equal(t, "aa@bb.com", user.Email)
	assert.Equal(t, "testUser", user.Username)
	assert.Equal(t, true, user.Admin)
	assert.Equal(t, 111, int(user.EnvironmentID))
}

func TestNewUser(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).
		WithArgs("testUser").
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(0))
	user, err := manager.New("testUser", "testPassword", "aa@bb.com", "Test Name", true, false)

	assert.NoError(t, err)

	assert.Equal(t, "aa@bb.com", user.Email)
	assert.Equal(t, "testUser", user.Username)
	assert.Equal(t, true, user.Admin)
}

func TestExistsUserFalse(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).
		WithArgs("testUser").
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(0))
	exists := manager.Exists("testUser")
	assert.Equal(t, false, exists)
}

func TestExistsUserTrue(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).
		WithArgs("testUser").
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))
	exists := manager.Exists("testUser")
	assert.Equal(t, true, exists)
}

func TestExistsGetUserTrue(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "username", "admin", "environment_id"}).
			AddRow("aa@bb.com", "testUser", true, 123))

	exists, user := manager.ExistsGet("testUser")

	assert.Equal(t, true, exists)
	assert.Equal(t, "aa@bb.com", user.Email)
	assert.Equal(t, "testUser", user.Username)
	assert.Equal(t, true, user.Admin)
	assert.Equal(t, 123, int(user.EnvironmentID))
}

func TestExistsGetUserFalse(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnError(fmt.Errorf("record not found"))

	exists, user := manager.ExistsGet("testUser")

	assert.Equal(t, false, exists)
	assert.Equal(t, "", user.Email)
	assert.Equal(t, "", user.Username)
	assert.Equal(t, false, user.Admin)
	assert.Equal(t, 0, int(user.EnvironmentID))
}

func TestUserIsAdmin(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE (username = $1 AND admin = $2) AND "admin_users"."deleted_at" IS NULL`)).
		WithArgs("testUser", true).
		WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

	admin := manager.IsAdmin("testUser")

	assert.Equal(t, true, admin)
}

func TestUserChangeAdmin(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "admin"}).AddRow(1, true))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "admin"=$1,"updated_at"=$2 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $3`)).
		WithArgs(false, sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ChangeAdmin("testUser", false)

	assert.NoError(t, err)
}

func TestUserChangeService(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "service"}).AddRow(1, true))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "service"=$1,"updated_at"=$2 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $3`)).
		WithArgs(false, sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ChangeService("testUser", false)

	assert.NoError(t, err)
}

func TestUserChangePassword(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "pass_hash"=$1,"updated_at"=$2 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $3`)).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ChangePassword("testUser", "testPassword")

	assert.NoError(t, err)
}

func TestUserChangeEmail(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "email"=$1,"updated_at"=$2 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $3`)).
		WithArgs("aa@bb.com", sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ChangeEmail("testUser", "aa@bb.com")

	assert.NoError(t, err)
}

func TestUserChangeFullname(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "fullname"=$1,"updated_at"=$2 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $3`)).
		WithArgs("Test User", sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ChangeFullname("testUser", "Test User")

	assert.NoError(t, err)
}

func TestUpdateTokenIPAddress(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "updated_at"=$1,"last_ip_address"=$2,"last_token_use"=$3 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $4`)).
		WithArgs(sqlmock.AnyArg(), "1.2.3.4", sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.UpdateTokenIPAddress("1.2.3.4", "testUser")

	assert.NoError(t, err)
}

func TestUpdateMetadata(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "updated_at"=$1,"csrf_token"=$2,"last_ip_address"=$3,"last_user_agent"=$4,"last_access"=$5 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $6`)).
		WithArgs(sqlmock.AnyArg(), "testCSRF", "1.2.3.4", "testUA", sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.UpdateMetadata("1.2.3.4", "testUA", "testUser", "testCSRF")

	assert.NoError(t, err)
}

func TestUpdateToken(t *testing.T) {
	manager, mock := setupTestManager(t)
	tt := time.Now()
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "updated_at"=$1,"api_token"=$2,"token_expire"=$3 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $4`)).
		WithArgs(sqlmock.AnyArg(), "testToken", tt, 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.UpdateToken("testUser", "testToken", tt)

	assert.NoError(t, err)
}

func TestDeleteUser(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("testUser", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`DELETE FROM "admin_users" WHERE "admin_users"."id" = $1`)).
		WithArgs(1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.Delete("testUser")

	assert.NoError(t, err)
}

func TestGetAllUsers(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE "admin_users"."deleted_at" IS NULL`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"email", "username", "admin", "environment_id", "service"}).
			AddRow("aa@bb.com", "testUser", true, 123, false))

	users, err := manager.All()
	assert.NoError(t, err)

	assert.Equal(t, 1, len(users))
}
