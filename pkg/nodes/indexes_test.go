package nodes

import (
	"slices"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// Check-ins and log batches rewrite these columns constantly. While no indexed
// column changes, Postgres applies those updates in place (HOT) without
// touching any index; indexing one of them would make every check-in maintain
// every index on the table.
func TestIndexesLeaveCheckinColumnsUnindexed(t *testing.T) {
	hot := []string{"last_seen", "ip_address", "bytes_received", "last_query_read"}
	for _, idx := range Indexes() {
		for _, c := range idx.Columns {
			if slices.Contains(hot, c) {
				t.Errorf("index %s covers %s, which every check-in rewrites", idx.Name, c)
			}
		}
	}
	// The struct tags must not index them either.
	s, err := schema.Parse(&OsqueryNode{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range s.ParseIndexes() {
		for _, f := range idx.Fields {
			if slices.Contains(hot, f.DBName) {
				t.Errorf("struct tag index %s covers %s, which every check-in rewrites", idx.Name, f.DBName)
			}
		}
	}
}
