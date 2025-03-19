package users

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
)

func TestPermissions(t *testing.T) {
	conf := config.JSONConfigurationJWT{
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
	var manager *UserManager
	t.Run("CreateUserManagerForPermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).WithArgs("admin_users", "BASE TABLE").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}), sqlmock.NewRows([]string{"RowsAffected"}).AddRow(1).AddRow(1))
		mock.ExpectExec(`CREATE TABLE "admin_users" .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1 AND table_type = $2`)).WithArgs("user_permissions", "BASE TABLE").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}), sqlmock.NewRows([]string{"RowsAffected"}).AddRow(1).AddRow(1))
		mock.ExpectExec(`CREATE TABLE "user_permissions" .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`CREATE INDEX IF NOT EXISTS .*`).WillReturnResult(sqlmock.NewResult(1, 1))

		manager = CreateUserManager(_postgres, &conf)

		assert.NotEqual(t, nil, manager)
	})
	t.Run("CreatePermission", func(t *testing.T) {
		tt := time.Now()
		perm := UserPermission{
			Username:      "testUser",
			AccessType:    0,
			AccessValue:   true,
			EnvironmentID: 111,
			Environment:   "testEnv",
			GrantedBy:     "test",
		}
		perm.CreatedAt = tt
		perm.UpdatedAt = tt

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "user_permissions" ("created_at","updated_at","deleted_at","username","access_type","access_value","environment","environment_id","granted_by") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING "id"`)).WithArgs(tt, tt, nil, perm.Username, perm.AccessType, perm.AccessValue, perm.Environment, perm.EnvironmentID, perm.GrantedBy).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.CreatePermission(perm)

		assert.NoError(t, err)

		assert.Equal(t, "testUser", perm.Username)
		assert.Equal(t, "test", perm.GrantedBy)
		assert.Equal(t, 111, int(perm.EnvironmentID))
		assert.Equal(t, "testEnv", perm.Environment)
	})
	t.Run("CreatePermissions", func(t *testing.T) {
		tt := time.Now()
		perm1 := UserPermission{
			Username:      "testUser1",
			AccessType:    0,
			AccessValue:   true,
			EnvironmentID: 111,
			Environment:   "testEnv",
			GrantedBy:     "test",
		}
		perm1.CreatedAt = tt
		perm1.UpdatedAt = tt
		perm2 := UserPermission{
			Username:      "testUser2",
			AccessType:    0,
			AccessValue:   true,
			EnvironmentID: 222,
			Environment:   "testEnv",
			GrantedBy:     "test",
		}
		perm2.CreatedAt = tt
		perm2.UpdatedAt = tt

		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "user_permissions" ("created_at","updated_at","deleted_at","username","access_type","access_value","environment","environment_id","granted_by") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING "id"`)).WithArgs(tt, tt, nil, perm1.Username, perm1.AccessType, perm1.AccessValue, perm1.Environment, perm1.EnvironmentID, perm1.GrantedBy).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		mock.ExpectBegin()
		mock.ExpectQuery(
			regexp.QuoteMeta(`INSERT INTO "user_permissions" ("created_at","updated_at","deleted_at","username","access_type","access_value","environment","environment_id","granted_by") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING "id"`)).WithArgs(tt, tt, nil, perm2.Username, perm2.AccessType, perm2.AccessValue, perm2.Environment, perm2.EnvironmentID, perm2.GrantedBy).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(456))
		mock.ExpectCommit()
		err := manager.CreatePermissions([]UserPermission{perm1, perm2})

		assert.NoError(t, err)

		assert.Equal(t, "testUser1", perm1.Username)
		assert.Equal(t, "test", perm1.GrantedBy)
		assert.Equal(t, 111, int(perm1.EnvironmentID))
		assert.Equal(t, "testEnv", perm1.Environment)
		assert.Equal(t, "testUser2", perm2.Username)
		assert.Equal(t, "test", perm2.GrantedBy)
		assert.Equal(t, 222, int(perm2.EnvironmentID))
		assert.Equal(t, "testEnv", perm2.Environment)
	})
	t.Run("GenEnvUserAccess", func(t *testing.T) {
		envs := []string{"env1", "env2"}
		access := manager.GenEnvUserAccess(envs, true, false, true, false)

		assert.Equal(t, true, access["env1"].User)
		assert.Equal(t, false, access["env1"].Query)
		assert.Equal(t, true, access["env1"].Carve)
		assert.Equal(t, false, access["env1"].Admin)
		assert.Equal(t, true, access["env2"].User)
		assert.Equal(t, false, access["env2"].Query)
		assert.Equal(t, true, access["env2"].Carve)
		assert.Equal(t, false, access["env2"].Admin)
	})
	t.Run("GenUserAccess", func(t *testing.T) {
		env := environments.TLSEnvironment{
			UUID: "testUUID",
		}
		envAccess := EnvAccess{
			User:  true,
			Query: false,
			Carve: true,
			Admin: false,
		}
		access := manager.GenUserAccess(env, envAccess)

		assert.Equal(t, true, access["testUUID"].User)
		assert.Equal(t, false, access["testUUID"].Query)
		assert.Equal(t, true, access["testUUID"].Carve)
		assert.Equal(t, false, access["testUUID"].Admin)
	})
	t.Run("GenUserPermission", func(t *testing.T) {
		perm := manager.GenUserPermission("testUser", "test", "testEnv", 111, false)

		assert.Equal(t, "testUser", perm.Username)
		assert.Equal(t, "testEnv", perm.Environment)
		assert.Equal(t, 111, perm.AccessType)
		assert.Equal(t, false, perm.AccessValue)
	})
	t.Run("GenPermissions", func(t *testing.T) {
		uAccess := make(UserAccess)
		envAccess := EnvAccess{
			User:  true,
			Query: false,
			Carve: true,
			Admin: false,
		}
		uAccess["testUUID"] = envAccess
		perms := manager.GenPermissions("testUser", "test", uAccess)

		assert.Equal(t, 4, len(perms))
	})
	t.Run("CheckPermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2) AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser", "testEnv").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value"}).AddRow("testUser", AdminLevel, true))

		access := manager.CheckPermissions("testUser", AdminLevel, "testEnv")

		assert.NoError(t, err)

		assert.Equal(t, true, access)
	})
	t.Run("CheckPermissionsNoEnv", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE (username = $1 AND admin = $2) AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser", true).WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		access := manager.CheckPermissions("testUser", AdminLevel, NoEnvironment)

		assert.NoError(t, err)

		assert.Equal(t, true, access)
	})
	t.Run("ChangePermissionMismatch", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		perm := UserPermission{
			Username:    "testUser",
			Environment: "testEnv",
			GrantedBy:   "test",
			AccessType:  int(AdminLevel),
			AccessValue: true,
		}
		err := manager.ChangePermission("testUser", "testEnv2", perm)

		assert.Error(t, err)
	})
	t.Run("ChangePermission", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectBegin()
		mock.ExpectExec(
			regexp.QuoteMeta(`UPDATE "user_permissions" SET "access_type"=$1,"access_value"=$2,"granted_by"=$3,"updated_at"=$4 WHERE "user_permissions"."deleted_at" IS NULL AND "id" = $5`)).WithArgs(AdminLevel, false, "test", sqlmock.AnyArg(), 1).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		perm := UserPermission{
			Username:    "testUser",
			Environment: "testEnv",
			GrantedBy:   "test",
			AccessType:  int(AdminLevel),
			AccessValue: false,
		}
		perm.ID = 1
		err := manager.ChangePermission("testUser", "testEnv", perm)

		assert.NoError(t, err)
	})
	t.Run("ChangePermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectBegin()
		mock.ExpectExec(
			regexp.QuoteMeta(`UPDATE "user_permissions" SET "access_type"=$1,"access_value"=$2,"granted_by"=$3,"updated_at"=$4 WHERE "user_permissions"."deleted_at" IS NULL AND "id" = $5`)).WithArgs(AdminLevel, false, "test", sqlmock.AnyArg(), 1).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		perm := UserPermission{
			Username:    "testUser",
			Environment: "testEnv",
			GrantedBy:   "test",
			AccessType:  int(AdminLevel),
			AccessValue: false,
		}
		perm.ID = 1
		err := manager.ChangePermissions("testUser", "testEnv", []UserPermission{perm})

		assert.NoError(t, err)
	})
	t.Run("ChangePermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectBegin()
		mock.ExpectExec(
			regexp.QuoteMeta(`UPDATE "user_permissions" SET "access_type"=$1,"access_value"=$2,"granted_by"=$3,"updated_at"=$4 WHERE "user_permissions"."deleted_at" IS NULL AND "id" = $5`)).WithArgs(AdminLevel, false, "test", sqlmock.AnyArg(), 1).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		perm := UserPermission{
			Username:    "testUser",
			Environment: "testEnv",
			GrantedBy:   "test",
			AccessType:  int(AdminLevel),
			AccessValue: false,
		}
		perm.ID = 1
		err := manager.ChangePermissions("testUser", "testEnv", []UserPermission{perm})

		assert.NoError(t, err)
	})
	t.Run("GetPermission", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", AdminLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, true, "test"))

		uPerm, err := manager.GetPermission("testUser", "testEnv", AdminLevel)

		assert.NoError(t, err)

		assert.Equal(t, "testUser", uPerm.Username)
		assert.Equal(t, "test", uPerm.GrantedBy)
		assert.Equal(t, int(AdminLevel), int(uPerm.AccessType))
		assert.Equal(t, true, uPerm.AccessValue)
	})
	t.Run("GetEnvPermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2) AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser", "testEnv").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, true, "test").AddRow("testUser", QueryLevel, true, "test"))

		uPerms, err := manager.GetEnvPermissions("testUser", "testEnv")

		assert.NoError(t, err)

		assert.Equal(t, 2, len(uPerms))
	})
	t.Run("GetAllPermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE username = $1 AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, true, "test").AddRow("testUser", QueryLevel, true, "test"))

		uPerms, err := manager.GetAllPermissions("testUser")

		assert.NoError(t, err)

		assert.Equal(t, 2, len(uPerms))
	})
	t.Run("SetEnvLevel", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", AdminLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, false, "test"))

		err := manager.SetEnvLevel("testUser", "testEnv", AdminLevel, true)

		assert.NoError(t, err)
	})
	t.Run("SetEnvAdmin", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", AdminLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, false, "test"))

		err := manager.SetEnvAdmin("testUser", "testEnv", true)

		assert.NoError(t, err)
	})
	t.Run("SetEnvCarve", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", CarveLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", CarveLevel, false, "test"))

		err := manager.SetEnvCarve("testUser", "testEnv", true)

		assert.NoError(t, err)
	})
	t.Run("SetEnvQuery", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", QueryLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", QueryLevel, false, "test"))

		err := manager.SetEnvQuery("testUser", "testEnv", true)

		assert.NoError(t, err)
	})
	t.Run("SetEnvUser", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", UserLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", UserLevel, false, "test"))

		err := manager.SetEnvUser("testUser", "testEnv", true)

		assert.NoError(t, err)
	})
	t.Run("ChangeAccess", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", UserLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", UserLevel, true, "test"))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", QueryLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", QueryLevel, false, "test"))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", CarveLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", CarveLevel, false, "test"))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2 AND access_type = $3) AND "user_permissions"."deleted_at" IS NULL ORDER BY "user_permissions"."id" LIMIT 1`)).WithArgs("testUser", "testEnv", AdminLevel).WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by"}).AddRow("testUser", AdminLevel, false, "test"))

		envAccess := EnvAccess{
			User:  true,
			Query: true,
			Carve: true,
			Admin: true,
		}
		err := manager.ChangeAccess("testUser", "testEnv", envAccess)

		assert.NoError(t, err)
	})
	t.Run("GetAccess", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE username = $1 AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by", "environment"}).AddRow("testUser", AdminLevel, true, "test", "testEnv").AddRow("testUser", UserLevel, true, "test", "testEnv").AddRow("testUser", CarveLevel, false, "test", "testEnv").AddRow("testUser", QueryLevel, false, "test", "testEnv"))

		uAccess, err := manager.GetAccess("testUser")

		assert.NoError(t, err)
		assert.Equal(t, 1, len(uAccess))
		for k, v := range uAccess {
			assert.Equal(t, "testEnv", k)
			assert.Equal(t, true, v.Admin)
			assert.Equal(t, true, v.User)
			assert.Equal(t, false, v.Query)
			assert.Equal(t, false, v.Carve)
		}
	})
	t.Run("GetEnvAccess", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2) AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser", "testEnv").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by", "environment"}).AddRow("testUser", AdminLevel, true, "test", "testEnv").AddRow("testUser", UserLevel, true, "test", "testEnv").AddRow("testUser", CarveLevel, false, "test", "testEnv").AddRow("testUser", QueryLevel, false, "test", "testEnv"))

		eAccess, err := manager.GetEnvAccess("testUser", "testEnv")

		assert.NoError(t, err)
		assert.Equal(t, true, eAccess.Admin)
		assert.Equal(t, true, eAccess.User)
		assert.Equal(t, false, eAccess.Query)
		assert.Equal(t, false, eAccess.Carve)
	})
	t.Run("DeleteEnvPermissions", func(t *testing.T) {
		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT count(*) FROM "admin_users" WHERE username = $1 AND "admin_users"."deleted_at" IS NULL`)).WithArgs("testUser").WillReturnRows(sqlmock.NewRows([]string{"count(*)"}).AddRow(1))

		mock.ExpectQuery(
			regexp.QuoteMeta(`SELECT * FROM "user_permissions" WHERE (username = $1 AND environment = $2) AND "user_permissions"."deleted_at" IS NULL`)).WithArgs("testUser", "testEnv").WillReturnRows(sqlmock.NewRows([]string{"username", "access_type", "access_value", "granted_by", "id"}).AddRow("testUser", AdminLevel, true, "test", 1).AddRow("testUser", QueryLevel, true, "test", 2))

		mock.ExpectBegin()
		mock.ExpectExec(
			regexp.QuoteMeta(`DELETE FROM "user_permissions" WHERE "user_permissions"."id" = $1`)).WithArgs(1).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		mock.ExpectBegin()
		mock.ExpectExec(
			regexp.QuoteMeta(`DELETE FROM "user_permissions" WHERE "user_permissions"."id" = $1`)).WithArgs(2).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		err := manager.DeleteEnvPermissions("testUser", "testEnv")

		assert.NoError(t, err)
	})
}
