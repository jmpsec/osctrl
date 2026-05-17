package users

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jmpsec/osctrl/pkg/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
)

func setupTestManager(t *testing.T) (*UserManager, sqlmock.Sqlmock) {
	conf := config.YAMLConfigurationJWT{
		JWTSecret:     "test-secret-must-be-at-least-32-bytes-long",
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

	manager := CreateUserManager(_postgres).WithJWT(&conf)
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
	assert.Equal(t, hashed[0:7], "$2a$12$")
}

func TestHashPasswordWithSalt(t *testing.T) {
	manager, _ := setupTestManager(t)
	hashed, err := manager.HashPasswordWithSalt("testPassword")
	assert.NoError(t, err)
	assert.Equal(t, hashed[0:7], "$2a$12$")
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

// TestCheckLoginCredentials_UnknownUserStillReturnsFalse confirms that
// the dummyHash compare introduced for timing-leak defense does NOT
// accidentally turn an unknown-user request into a successful login.
// The compare result must be discarded; the function returns false.
func TestCheckLoginCredentials_UnknownUserStillReturnsFalse(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("doesNotExist", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	access, user := manager.CheckLoginCredentials("doesNotExist", "any-password")
	assert.Equal(t, false, access)
	assert.Equal(t, AdminUser{}, user)
}

// TestCheckLoginCredentials_TimingEqualization asserts the
// username-enumeration timing defense: the wall-clock time of
// "valid user, wrong password" (real bcrypt compare) and "unknown
// user" (dummy bcrypt compare) must be within 2× of each other.
//
// Before the fix the ratio was ~10–15× (pentest finding: 15-25ms vs
// 300ms). The threshold is loose enough that GC pauses or scheduler
// jitter on CI won't flake the test, but tight enough that a
// regression (e.g. someone deletes the dummyHash compare) jumps the
// ratio well past 2× and fails the test.
//
// Skipped under -short because the bcrypt-cost-12 hash budgets ~300ms
// per call and the test runs N iterations.
func TestCheckLoginCredentials_TimingEqualization(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	manager, mock := setupTestManager(t)
	hashed, err := manager.HashPasswordWithSalt("realPassword")
	assert.NoError(t, err)

	const iters = 4
	// Each iteration burns ~300ms of bcrypt work × 2 paths × iters,
	// so the test runs in ~2-3 seconds locally.
	for i := 0; i < iters; i++ {
		// valid-user-wrong-password path
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
			WithArgs("knownUser", 1).
			WillReturnRows(sqlmock.NewRows([]string{"email", "username", "pass_hash", "admin", "environment_id", "service"}).
				AddRow("aa@bb.com", "knownUser", hashed, true, 1, false))
		// unknown-user path
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
			WithArgs("unknownUser", 1).
			WillReturnError(gorm.ErrRecordNotFound)
	}

	knownTimes := make([]time.Duration, iters)
	unknownTimes := make([]time.Duration, iters)
	for i := 0; i < iters; i++ {
		t0 := time.Now()
		manager.CheckLoginCredentials("knownUser", "wrong-password")
		knownTimes[i] = time.Since(t0)
		t1 := time.Now()
		manager.CheckLoginCredentials("unknownUser", "wrong-password")
		unknownTimes[i] = time.Since(t1)
	}

	medKnown := median(knownTimes)
	medUnknown := median(unknownTimes)
	ratio := float64(medKnown) / float64(medUnknown)
	if ratio < 1 {
		ratio = 1 / ratio
	}
	t.Logf("known=%v unknown=%v ratio=%.2fx", medKnown, medUnknown, ratio)
	if ratio > 2.0 {
		t.Errorf("timing-leak regression: known=%v unknown=%v ratio=%.2fx (want < 2.0x)", medKnown, medUnknown, ratio)
	}
}

// median returns the median of a slice of durations. Robust to a single
// GC pause or scheduling stutter that would skew the mean.
func median(xs []time.Duration) time.Duration {
	cp := make([]time.Duration, len(xs))
	copy(cp, xs)
	// insertion sort — tiny inputs
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j-1], cp[j] = cp[j], cp[j-1]
		}
	}
	return cp[len(cp)/2]
}

func TestCreateCheckToken(t *testing.T) {
	manager, _ := setupTestManager(t)
	conf := config.YAMLConfigurationJWT{
		JWTSecret: "test-secret-must-be-at-least-32-bytes-long",
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

// TestCheckTokenRejectsNoneAlg locks in the key-func's alg-pinning behaviour:
// even if a forged token bypasses the library's own none-mitigation, our
// explicit `*jwt.SigningMethodHMAC` type-assertion refuses it.
func TestCheckTokenRejectsNoneAlg(t *testing.T) {
	manager, _ := setupTestManager(t)
	// Hand-build a token signed with alg:none. golang-jwt requires
	// jwt.UnsafeAllowNoneSignatureType as the key for SignedString to succeed.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"username": "attacker"})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	assert.NoError(t, err)
	_, valid := manager.CheckToken("test-secret-must-be-at-least-32-bytes-long", signed)
	assert.False(t, valid, "alg:none tokens must be rejected by the key-func")
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
		regexp.QuoteMeta(`INSERT INTO "admin_users" ("created_at","updated_at","deleted_at","username","email","fullname","pass_hash","api_token","token_expire","admin","service","uuid","csrf_token","last_ip_address","last_user_agent","last_access","last_token_use","environment_id","auth_source") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING "id"`)).
		WithArgs(tt, tt, nil, user.Username, user.Email, user.Fullname, user.PassHash, user.APIToken, tt, user.Admin, user.Service, user.UUID, user.CSRFToken, user.LastIPAddress, user.LastUserAgent, tt, tt, user.EnvironmentID, user.AuthSource).
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
	// UpdateToken now also clears csrf_token alongside api_token /
	// token_expire so a stale CSRF cookie can't outlive its session.
	//
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "api_token"=$1,"csrf_token"=$2,"token_expire"=$3,"updated_at"=$4 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $5`)).
		WithArgs("testToken", "", tt, sqlmock.AnyArg(), 1).
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

// TestUpdateTokenClearsCSRF locks the contract that rotating APIToken
// also clears CSRFToken so a stale CSRF cookie can't outlive its
// session.
func TestUpdateTokenClearsCSRF(t *testing.T) {
	manager, mock := setupTestManager(t)
	tt := time.Now()
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("alice", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "api_token"=$1,"csrf_token"=$2,"token_expire"=$3,"updated_at"=$4 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $5`)).
		WithArgs("freshtoken", "", tt, sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.UpdateToken("alice", "freshtoken", tt)
	assert.NoError(t, err)
}

// TestClearTokenAlsoClearsCSRF locks the contract that DELETE
// /users/{u}/token wipes both api_token and csrf_token.
func TestClearTokenAlsoClearsCSRF(t *testing.T) {
	manager, mock := setupTestManager(t)
	mock.ExpectQuery(
		regexp.QuoteMeta(`SELECT * FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL ORDER BY "admin_users"."id" LIMIT $2`)).
		WithArgs("bob", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

	mock.ExpectBegin()
	mock.ExpectExec(
		regexp.QuoteMeta(`UPDATE "admin_users" SET "api_token"=$1,"csrf_token"=$2,"token_expire"=$3,"updated_at"=$4 WHERE "admin_users"."deleted_at" IS NULL AND "id" = $5`)).
		WithArgs("", "", sqlmock.AnyArg(), sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := manager.ClearToken("bob")
	assert.NoError(t, err)
}
