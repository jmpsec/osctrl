package main

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
)

func TestNodeToRowActiveInactive(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		seen   time.Time
		hours  int64
		active bool
	}{
		{"fresh", now, 24, true},
		{"just_within", now.Add(-23 * time.Hour), 24, true},
		{"stale", now.Add(-48 * time.Hour), 24, false},
		{"zero_hours_defaults_active", now.Add(-1 * time.Hour), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := nodes.OsqueryNode{UUID: "ABC", Hostname: "h", LastSeen: c.seen, Environment: "dev"}
			row := nodeToRow(n, c.hours)
			if row.Active != c.active {
				t.Fatalf("expected active=%v got %v", c.active, row.Active)
			}
			if row.UUID != "ABC" {
				t.Fatalf("uuid not mapped: %q", row.UUID)
			}
		})
	}
}

func TestQueryStatus(t *testing.T) {
	cases := []struct {
		q    queries.DistributedQuery
		want string
	}{
		{queries.DistributedQuery{Active: true}, "ACTIVE"},
		{queries.DistributedQuery{Completed: true}, "COMPLETE"},
		{queries.DistributedQuery{Expired: true}, "EXPIRED"},
		{queries.DistributedQuery{Deleted: true}, "DELETED"},
		{queries.DistributedQuery{}, "—"},
	}
	for _, c := range cases {
		if got := queryStatus(c.q); got != c.want {
			t.Fatalf("queryStatus: got %q want %q", got, c.want)
		}
	}
}

func TestCsvSplit(t *testing.T) {
	got := csvSplit("a, b ,, c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d got %q want %q", i, got[i], want[i])
		}
	}
	if csvSplit("") != nil {
		t.Fatalf("empty should be nil")
	}
}

func TestParseHidden(t *testing.T) {
	for _, v := range []string{"yes", "Y", "true", "1"} {
		if !parseHidden(v) {
			t.Fatalf("expected hidden for %q", v)
		}
	}
	for _, v := range []string{"", "no", "0", "x"} {
		if parseHidden(v) {
			t.Fatalf("expected not hidden for %q", v)
		}
	}
}
