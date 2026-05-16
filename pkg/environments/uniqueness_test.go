package environments

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB returns a fresh SQLite-in-memory DB with TLSEnvironment
// migrated, and TranslateError enabled so the test can assert against
// gorm.ErrDuplicatedKey across drivers. Each test gets its own DB
// keyed by t.Name() so parallel test runs don't share state.
//
// We use cache=shared + a per-test DB name so the concurrent test
// below sees the same table across all goroutine connections. With
// the default ":memory:" each new connection gets its own empty DB
// and the goroutines would see "no such table".
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:env_test_" + t.Name() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Force a single underlying connection so SQLite's per-connection
	// memory DB doesn't materialize multiple isolated databases.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&TLSEnvironment{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return db
}

// TestUniqueIndexOnName confirms the schema-level uniqueIndex on
// tls_environments.name is in place and raises gorm.ErrDuplicatedKey
// (via TranslateError) when a second insert collides on name.
func TestUniqueIndexOnName(t *testing.T) {
	db := setupTestDB(t)

	a := TLSEnvironment{UUID: "uuid-a", Name: "dev", Hostname: "a.example.com"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatalf("first insert should succeed: %v", err)
	}

	b := TLSEnvironment{UUID: "uuid-b", Name: "dev", Hostname: "b.example.com"}
	err := db.Create(&b).Error
	if err == nil {
		t.Fatal("second insert with the same name should fail")
	}
	if !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("expected gorm.ErrDuplicatedKey, got %T: %v", err, err)
	}
}

// TestUniqueIndexCaseSensitive confirms the constraint is case-sensitive
// at the DB level. Callers (handlers, CLI) are responsible for
// lowercasing input before validation — this test asserts the storage
// layer's behavior so the contract is documented and locked.
func TestUniqueIndexCaseSensitive(t *testing.T) {
	db := setupTestDB(t)

	a := TLSEnvironment{UUID: "uuid-a", Name: "dev", Hostname: "a.example.com"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// `Dev` is a different string than `dev` to the constraint. Bypassing
	// EnvNameFilter at the package layer (which would reject `Dev`) is
	// deliberate — we are exercising the storage contract, not the
	// validator.
	b := TLSEnvironment{UUID: "uuid-b", Name: "Dev", Hostname: "b.example.com"}
	if err := db.Create(&b).Error; err != nil {
		t.Fatalf("Dev should be storable as distinct from dev: %v", err)
	}
}

// TestUniqueIndexRenameCollision confirms an UPDATE that renames an env
// to an existing name fails with gorm.ErrDuplicatedKey. This is the
// PATCH-handler race-fallback path: even if Exists() passes, the
// constraint catches concurrent renames.
func TestUniqueIndexRenameCollision(t *testing.T) {
	db := setupTestDB(t)

	a := TLSEnvironment{UUID: "uuid-a", Name: "dev", Hostname: "a.example.com"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatalf("create a: %v", err)
	}
	b := TLSEnvironment{UUID: "uuid-b", Name: "prod", Hostname: "b.example.com"}
	if err := db.Create(&b).Error; err != nil {
		t.Fatalf("create b: %v", err)
	}

	// Rename b → "dev" should fail.
	err := db.Model(&b).Updates(map[string]interface{}{"name": "dev"}).Error
	if err == nil {
		t.Fatal("rename to existing name should fail")
	}
	if !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("expected gorm.ErrDuplicatedKey, got %T: %v", err, err)
	}
}

// TestUniqueIndexConcurrentInsert races N goroutines all trying to
// insert the same env name. The test asserts exactly one wins; all
// others get gorm.ErrDuplicatedKey. This is the storage-level
// guarantee the create-handler race-fallback relies on.
func TestUniqueIndexConcurrentInsert(t *testing.T) {
	db := setupTestDB(t)

	const N = 16
	var wg sync.WaitGroup
	var wins int32
	var dups int32
	var other atomic.Value // first non-dup, non-success error

	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			row := TLSEnvironment{
				UUID:     "uuid-" + string(rune('a'+i)),
				Name:     "racy", // same name for every goroutine
				Hostname: "h.example.com",
			}
			err := db.Create(&row).Error
			switch {
			case err == nil:
				atomic.AddInt32(&wins, 1)
			case errors.Is(err, gorm.ErrDuplicatedKey):
				atomic.AddInt32(&dups, 1)
			default:
				other.Store(err)
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("expected exactly 1 winner, got %d (dups=%d)", wins, dups)
	}
	if dups != N-1 {
		t.Fatalf("expected %d dup-key losers, got %d (wins=%d)", N-1, dups, wins)
	}
	if v := other.Load(); v != nil {
		t.Fatalf("unexpected non-dup error during race: %v", v)
	}
}
