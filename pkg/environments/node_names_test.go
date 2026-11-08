package environments

import (
	"errors"
	"testing"

	"github.com/jmpsec/osctrl/pkg/settings"
)

// nodeTables creates minimal stand-ins for the name-keyed tables (pkg/nodes
// and pkg/posture can't be imported here: they import this package).
func nodeTables(t *testing.T, m *EnvManager) {
	t.Helper()
	if err := m.DB.AutoMigrate(&settings.SettingValue{}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE osquery_nodes (id INTEGER PRIMARY KEY, environment TEXT, deleted_at DATETIME)",
		"CREATE TABLE node_posture (id INTEGER PRIMARY KEY, environment TEXT)",
	} {
		if err := m.DB.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func countIn(t *testing.T, m *EnvManager, table, env string) int64 {
	t.Helper()
	var n int64
	if err := m.DB.Table(table).Where("environment = ?", env).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func newEnv(t *testing.T, m *EnvManager, name, uuid string) TLSEnvironment {
	t.Helper()
	if err := m.Create(&TLSEnvironment{Name: name, UUID: uuid}); err != nil {
		t.Fatal(err)
	}
	env, err := m.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestDeleteRefusesEnvWithNodes(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	nodeTables(t, m)
	newEnv(t, m, "prod", "uuid-prod")
	m.DB.Exec("INSERT INTO osquery_nodes (environment) VALUES ('prod')")

	if err := m.Delete("prod"); !errors.Is(err, ErrEnvHasNodes) {
		t.Fatalf("want ErrEnvHasNodes, got %v", err)
	}
	if !m.Exists("prod") {
		t.Fatal("env deleted despite nodes")
	}
	// Soft-deleted nodes don't block.
	m.DB.Exec("UPDATE osquery_nodes SET deleted_at = CURRENT_TIMESTAMP")
	if err := m.Delete("prod"); err != nil {
		t.Fatalf("delete with only soft-deleted nodes: %v", err)
	}
}

func TestCreateRefusesNameCarriedByOrphanedNodes(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	nodeTables(t, m)
	m.DB.Exec("INSERT INTO osquery_nodes (environment) VALUES ('prod')")
	if err := m.Create(&TLSEnvironment{Name: "prod", UUID: "uuid-new"}); !errors.Is(err, ErrNameHasNodes) {
		t.Fatalf("want ErrNameHasNodes, got %v", err)
	}
	if m.Exists("prod") {
		t.Fatal("env created over orphaned nodes")
	}
}

func TestUpdateFieldsRenameMovesNameKeyedRows(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	nodeTables(t, m)
	env := newEnv(t, m, "prod", "uuid-prod")
	m.DB.Exec("INSERT INTO osquery_nodes (environment) VALUES ('prod'), ('prod'), ('dev')")
	m.DB.Exec("INSERT INTO node_posture (environment) VALUES ('prod')")

	// A non-name patch leaves nodes alone.
	if err := m.UpdateFields(env, map[string]interface{}{"hostname": "h.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := countIn(t, m, "osquery_nodes", "prod"); got != 2 {
		t.Fatalf("nodes moved on non-rename patch: %d", got)
	}

	if err := m.UpdateFields(env, map[string]interface{}{"name": "prod-old"}); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int64{"osquery_nodes": 2, "node_posture": 1} {
		if got := countIn(t, m, table, "prod"); got != 0 {
			t.Fatalf("%s: %d rows left under old name", table, got)
		}
		if got := countIn(t, m, table, "prod-old"); got != want {
			t.Fatalf("%s: want %d under new name, got %d", table, want, got)
		}
	}
	if got := countIn(t, m, "osquery_nodes", "dev"); got != 1 {
		t.Fatalf("other env's nodes touched: %d", got)
	}
}

func TestUpdateFieldsRenameMovesQueryTargets(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	nodeTables(t, m)
	if err := m.DB.Exec("CREATE TABLE distributed_query_targets (id INTEGER PRIMARY KEY, type TEXT, value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	env := newEnv(t, m, "prod", "uuid-prod")
	m.DB.Exec(`INSERT INTO distributed_query_targets (type, value) VALUES
		('environment', 'prod'), ('environment', 'uuid-prod'), ('platform', 'prod'), ('environment', 'dev')`)

	if err := m.UpdateFields(env, map[string]interface{}{"name": "prod-old"}); err != nil {
		t.Fatal(err)
	}
	count := func(typ, value string) int64 {
		var n int64
		m.DB.Table("distributed_query_targets").Where("type = ? AND value = ?", typ, value).Count(&n)
		return n
	}
	for _, c := range []struct {
		typ, value string
		want       int64
	}{
		{"environment", "prod", 0},
		{"environment", "prod-old", 1},
		{"environment", "uuid-prod", 1}, // UUID targets survive renames as is
		{"platform", "prod", 1},         // only environment targets are names
		{"environment", "dev", 1},
	} {
		if got := count(c.typ, c.value); got != c.want {
			t.Fatalf("%s=%s: want %d, got %d", c.typ, c.value, c.want, got)
		}
	}
}

func TestUpdateFieldsRenameRefusesNameCarriedByNodes(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	nodeTables(t, m)
	env := newEnv(t, m, "prod", "uuid-prod")
	m.DB.Exec("INSERT INTO osquery_nodes (environment) VALUES ('prod'), ('ghost')")

	err := m.UpdateFields(env, map[string]interface{}{"name": "ghost", "hostname": "h.example.com"})
	if !errors.Is(err, ErrNameHasNodes) {
		t.Fatalf("want ErrNameHasNodes, got %v", err)
	}
	got, _ := m.Get("uuid-prod")
	if got.Name != "prod" || got.Hostname == "h.example.com" {
		t.Fatalf("patch partially applied: %+v", got)
	}
	if n := countIn(t, m, "osquery_nodes", "prod"); n != 1 {
		t.Fatalf("nodes moved: %d", n)
	}
}
