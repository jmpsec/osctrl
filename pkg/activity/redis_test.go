package activity

import (
	"context"
	"testing"
	"time"
)

func TestDayKeyUsesEnvNodeAndUTCDate(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*60*60)
	day := time.Date(2026, 6, 16, 1, 33, 0, 0, loc)

	got := DayKey("nodeact:v1", "ENV1", "NODE1", day)
	want := "nodeact:v1:ENV1:NODE1:20260615"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	if got := bucketHour(day); got != 23 {
		t.Fatalf("expected UTC bucket hour 23, got %d", got)
	}

	wantDayStart := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	if got := dayStart(day); !got.Equal(wantDayStart) {
		t.Fatalf("expected UTC day start %s, got %s", wantDayStart, got)
	}

	gotEnv := EnvDayKey("nodeact:v1", "ENV1", day)
	wantEnv := "nodeact:v1:env:ENV1:20260615"
	if gotEnv != wantEnv {
		t.Fatalf("expected env key %q, got %q", wantEnv, gotEnv)
	}
}

func TestStoreIncrementManyAndReadSeries(t *testing.T) {
	client, fake := newTestRedisClient(t)
	store := NewRedisStore(client, "nodeact:v1", 7, 24*time.Hour)

	ctx := context.Background()
	end := time.Date(2026, 6, 15, 23, 50, 0, 0, time.UTC)
	loc := time.FixedZone("UTC+2", 2*60*60)

	err := store.IncrementMany(context.Background(), []Event{
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventStatus, At: time.Date(2026, 6, 14, 23, 20, 0, 0, time.UTC), Count: 2},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventQueryRead, At: time.Date(2026, 6, 15, 0, 5, 0, 0, time.UTC), Count: 1},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventResult, At: time.Date(2026, 6, 15, 10, 10, 0, 0, time.UTC), Count: 40000},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventResult, At: time.Date(2026, 6, 15, 10, 40, 0, 0, time.UTC), Count: 30000},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventQueryWrite, At: time.Date(2026, 6, 15, 11, 20, 0, 0, time.UTC), Count: 1},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventEnroll, At: time.Date(2026, 6, 16, 1, 20, 0, 0, loc), Count: 3},
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventConfig, At: time.Date(2026, 6, 15, 11, 20, 0, 0, time.UTC), Count: 0},
	})
	if err != nil {
		t.Fatalf("increment failed: %v", err)
	}

	out, err := store.ReadSeries(ctx, "ENV1", []string{"NODE1", "NODE2"}, end, 2)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	series := out["NODE1"]
	if len(series.Total) != 48 {
		t.Fatalf("expected 48 buckets, got %d", len(series.Total))
	}

	wantStart := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	if !series.Start.Equal(wantStart) {
		t.Fatalf("expected start %s, got %s", wantStart, series.Start)
	}

	if series.Status[23] != 2 || series.Total[23] != 2 {
		t.Fatalf("expected day 1 hour 23 status bucket to be 2, got status=%d total=%d", series.Status[23], series.Total[23])
	}
	if series.QueryRead[24] != 1 || series.Total[24] != 1 {
		t.Fatalf("expected day 2 hour 0 query-read bucket to be 1, got queryRead=%d total=%d", series.QueryRead[24], series.Total[24])
	}
	if series.Result[34] != 65535 || series.Total[34] != 65535 {
		t.Fatalf("expected saturated result bucket at day 2 hour 10, got result=%d total=%d", series.Result[34], series.Total[34])
	}
	if series.QueryWrite[35] != 1 || series.Total[35] != 1 {
		t.Fatalf("expected day 2 hour 11 query-write bucket to be 1, got queryWrite=%d total=%d", series.QueryWrite[35], series.Total[35])
	}
	if series.Enroll[47] != 3 || series.Total[47] != 3 {
		t.Fatalf("expected UTC-normalized enroll bucket at day 2 hour 23 to be 3, got enroll=%d total=%d", series.Enroll[47], series.Total[47])
	}
	if series.Config[35] != 0 {
		t.Fatalf("expected zero-count config event to be ignored, got %d", series.Config[35])
	}
	if series.Total[0] != 0 || series.Total[1] != 0 || series.Total[46] != 0 {
		t.Fatalf("expected missing buckets to stay zero-filled, got total[0]=%d total[1]=%d total[46]=%d", series.Total[0], series.Total[1], series.Total[46])
	}
	if got := fake.expireFor("nodeact:v1:ENV1:NODE1:20260614"); got != 24*time.Hour {
		t.Fatalf("expected 24h TTL for 20260614 key, got %s", got)
	}
	if got := fake.expireFor("nodeact:v1:ENV1:NODE1:20260615"); got != 24*time.Hour {
		t.Fatalf("expected 24h TTL for 20260615 key, got %s", got)
	}
	if got := fake.expireFor("nodeact:v1:env:ENV1:20260614"); got != 24*time.Hour {
		t.Fatalf("expected 24h TTL for env 20260614 key, got %s", got)
	}
	if got := fake.expireFor("nodeact:v1:env:ENV1:20260615"); got != 24*time.Hour {
		t.Fatalf("expected 24h TTL for env 20260615 key, got %s", got)
	}

	empty := out["NODE2"]
	if len(empty.Total) != 48 {
		t.Fatalf("expected NODE2 to have 48 buckets, got %d", len(empty.Total))
	}
	for i, value := range empty.Total {
		if value != 0 {
			t.Fatalf("expected NODE2 bucket %d to be zero-filled, got %d", i, value)
		}
	}
}

func TestStoreReadEnvSeries(t *testing.T) {
	client, fake := newTestRedisClient(t)
	store := NewRedisStore(client, "nodeact:v1", 7, 24*time.Hour)

	ctx := context.Background()
	end := time.Date(2026, 6, 15, 23, 50, 0, 0, time.UTC)

	err := store.IncrementMany(ctx, []Event{
		{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: EventStatus, At: time.Date(2026, 6, 15, 11, 20, 0, 0, time.UTC), Count: 2},
		{EnvUUID: "ENV1", NodeUUID: "NODE2", Type: EventStatus, At: time.Date(2026, 6, 15, 11, 40, 0, 0, time.UTC), Count: 1},
		{EnvUUID: "ENV1", NodeUUID: "NODE2", Type: EventQueryRead, At: time.Date(2026, 6, 15, 12, 5, 0, 0, time.UTC), Count: 4},
		{EnvUUID: "ENV1", NodeUUID: "NODE3", Type: EventEnroll, At: time.Date(2026, 6, 15, 12, 10, 0, 0, time.UTC), Count: 1},
		{EnvUUID: "ENV2", NodeUUID: "NODE9", Type: EventResult, At: time.Date(2026, 6, 15, 12, 10, 0, 0, time.UTC), Count: 7},
	})
	if err != nil {
		t.Fatalf("increment failed: %v", err)
	}

	series, err := store.ReadEnvSeries(ctx, "ENV1", end, 1)
	if err != nil {
		t.Fatalf("read env series failed: %v", err)
	}

	if len(series.Total) != 24 {
		t.Fatalf("expected 24 buckets, got %d", len(series.Total))
	}

	wantStart := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	if !series.Start.Equal(wantStart) {
		t.Fatalf("expected start %s, got %s", wantStart, series.Start)
	}

	if series.Status[11] != 3 {
		t.Fatalf("expected env status bucket 11 to be 3, got %d", series.Status[11])
	}
	if series.QueryRead[12] != 4 {
		t.Fatalf("expected env query-read bucket 12 to be 4, got %d", series.QueryRead[12])
	}
	if series.Enroll[12] != 1 {
		t.Fatalf("expected env enroll bucket 12 to be 1, got %d", series.Enroll[12])
	}
	if series.Total[11] != 3 || series.Total[12] != 5 {
		t.Fatalf("unexpected env totals bucket11=%d bucket12=%d", series.Total[11], series.Total[12])
	}
	if series.Result[12] != 0 {
		t.Fatalf("expected ENV2 result data not to leak into ENV1, got %d", series.Result[12])
	}
	if got := fake.expireFor("nodeact:v1:env:ENV1:20260615"); got != 24*time.Hour {
		t.Fatalf("expected env key TTL to be 24h, got %s", got)
	}
}
