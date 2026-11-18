package santa

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Two transactions that both see no rule and then create it at the same moment,
// as two votes crossing the global threshold do (#1214). SQLite in memory
// cannot run them concurrently, so this needs a real engine.
func TestAllowRuleConcurrent(t *testing.T) {
	for _, backend := range []string{"POSTGRES", "MYSQL"} {
		t.Run(backend, func(t *testing.T) {
			dsn := os.Getenv("OSCTRL_TEST_" + backend + "_DSN")
			if dsn == "" {
				t.Skip("set OSCTRL_TEST_" + backend + "_DSN to test this engine")
			}
			dialect := postgres.Open(dsn)
			if backend == "MYSQL" {
				dialect = mysql.Open(dsn)
			}
			db, err := gorm.Open(dialect, &gorm.Config{})
			require.NoError(t, err)
			if db.Migrator().HasTable(&Rule{}) {
				t.Skip("santa_rules already exists; use an empty test database")
			}
			require.NoError(t, db.AutoMigrate(&Rule{}))
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&Rule{})) })

			rule := Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: strings.Repeat("ef", 32), Policy: "ALLOWLIST", Scope: "env", CreatedBy: VoteRuleCreator}
			var ready, done sync.WaitGroup
			ready.Add(2)
			done.Add(2)
			errs := make([]error, 2)
			created := make([]bool, 2)
			for i := range 2 {
				go func() {
					defer done.Done()
					errs[i] = db.Transaction(func(tx *gorm.DB) error {
						var n int64
						err := tx.Model(&Rule{}).Count(&n).Error
						ready.Done()
						ready.Wait()
						if err != nil {
							return err
						}
						_, created[i], err = allowRule(tx, rule)
						return err
					})
				}()
			}
			done.Wait()
			require.NoError(t, errs[0])
			require.NoError(t, errs[1])
			require.NotEqual(t, created[0], created[1], "exactly one transaction creates the rule")
			var n int64
			require.NoError(t, db.Model(&Rule{}).Count(&n).Error)
			require.EqualValues(t, 1, n)
		})
	}
}

// The vote or approval that loses a race finds the rule already there (#1214).
func TestAllowRuleExisting(t *testing.T) {
	sha := strings.Repeat("cd", 32)
	allow := Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: sha, Policy: "ALLOWLIST", Scope: "env", CreatedBy: VoteRuleCreator}
	for _, tt := range []struct {
		name        string
		existing    string // policy already stored, "" for none
		wantCreated bool
		wantErr     error
	}{
		{"none", "", true, nil},
		{"allow", "ALLOWLIST", false, nil},
		{"compiler", "ALLOWLIST_COMPILER", false, nil},
		{"block", "BLOCKLIST", false, ErrRuleConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t)
			if tt.existing != "" {
				r := allow
				r.Policy = tt.existing
				require.NoError(t, m.DB.Create(&r).Error)
			}
			require.NoError(t, m.DB.Transaction(func(tx *gorm.DB) error {
				got, created, err := allowRule(tx, allow)
				require.ErrorIs(t, err, tt.wantErr)
				require.Equal(t, tt.wantCreated, created)
				if err == nil {
					require.NotZero(t, got.ID)
				}
				// The transaction is still usable after the skipped insert.
				var n int64
				return tx.Model(&Rule{}).Count(&n).Error
			}))
			var n int64
			require.NoError(t, m.DB.Model(&Rule{}).Count(&n).Error)
			require.EqualValues(t, 1, n)
		})
	}
}
