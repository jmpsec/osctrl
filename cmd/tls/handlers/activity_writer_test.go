package handlers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
)

type recordingActivityStore struct {
	mu      sync.Mutex
	events  []activity.Event
	notify  chan struct{}
	blocked chan struct{}
	release chan struct{}
}

func (s *recordingActivityStore) IncrementMany(_ context.Context, events []activity.Event) error {
	s.mu.Lock()
	s.events = append(s.events, events...)
	s.mu.Unlock()

	if s.blocked != nil {
		select {
		case s.blocked <- struct{}{}:
		default:
		}
	}
	if s.notify != nil {
		select {
		case s.notify <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		<-s.release
	}

	return nil
}

func (s *recordingActivityStore) snapshot() []activity.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]activity.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestActivityWriterFlushesAggregatedEvents(t *testing.T) {
	store := &recordingActivityStore{
		notify: make(chan struct{}, 1),
	}
	writer := NewActivityWriter(store, 2, time.Second, 8)
	defer writer.close()

	now := time.Date(2026, 6, 15, 11, 25, 0, 0, time.UTC)
	writer.addEvent(activity.Event{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: activity.EventStatus, At: now})
	writer.addEvent(activity.Event{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: activity.EventStatus, At: now.Add(20 * time.Minute)})

	select {
	case <-store.notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for activity flush")
	}

	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 aggregated event, got %+v", events)
	}

	got := events[0]
	if got.Count != 2 {
		t.Fatalf("expected aggregated count 2, got %d", got.Count)
	}
	wantAt := time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC)
	if !got.At.Equal(wantAt) {
		t.Fatalf("expected normalized hour %s, got %s", wantAt, got.At)
	}
}

func TestActivityWriterDropsWhenQueueIsFullWithoutBlocking(t *testing.T) {
	store := &recordingActivityStore{
		blocked: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	writer := NewActivityWriter(store, 1, time.Hour, 1)

	now := time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC)
	writer.addEvent(activity.Event{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: activity.EventStatus, At: now})

	select {
	case <-store.blocked:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first flush to block")
	}

	writer.addEvent(activity.Event{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: activity.EventStatus, At: now.Add(time.Hour)})

	done := make(chan struct{})
	go func() {
		writer.addEvent(activity.Event{EnvUUID: "ENV1", NodeUUID: "NODE1", Type: activity.EventStatus, At: now.Add(2 * time.Hour)})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected addEvent to return immediately when queue is full")
	}

	close(store.release)
	writer.close()

	events := store.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 flushed events after dropping one, got %+v", events)
	}
}

func TestRecordActivityEmitsTypedEvent(t *testing.T) {
	store := &recordingActivityStore{notify: make(chan struct{}, 1)}
	writer := NewActivityWriter(store, 1, time.Second, 4)
	defer writer.close()

	h := &HandlersTLS{ActivityWriter: writer}
	h.recordActivity("ENV-UUID", "NODE-UUID", activity.EventConfig)

	select {
	case <-store.notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for activity flush")
	}

	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := events[0]
	if got.EnvUUID != "ENV-UUID" || got.NodeUUID != "NODE-UUID" || got.Type != activity.EventConfig || got.Count != 1 {
		t.Fatalf("unexpected event: %+v", got)
	}
}

func TestRecordActivityIsNoopWhenNotConfiguredOrMissingIDs(t *testing.T) {
	store := &recordingActivityStore{notify: make(chan struct{}, 1)}
	writer := NewActivityWriter(store, 1, time.Second, 4)
	defer writer.close()

	// Nil handler must not panic.
	var h *HandlersTLS
	h.recordActivity("ENV", "NODE", activity.EventStatus)

	// No writer attached -> no event.
	h = &HandlersTLS{}
	h.recordActivity("ENV", "NODE", activity.EventStatus)

	// Empty env/node UUID -> no event (would corrupt per-node rollup keys).
	h = &HandlersTLS{ActivityWriter: writer}
	h.recordActivity("", "NODE", activity.EventStatus)
	h.recordActivity("ENV", "", activity.EventStatus)

	if len(store.snapshot()) != 0 {
		t.Fatalf("expected no events for nil/empty cases, got %d", len(store.snapshot()))
	}
}

func TestLogActivityTypeMapping(t *testing.T) {
	cases := []struct {
		in   string
		want activity.EventType
		ok   bool
	}{
		{"status", activity.EventStatus, true},
		{"result", activity.EventResult, true},
		{"", 0, false},
		{"results", 0, false},
		{"STATUS", 0, false},
	}
	for _, c := range cases {
		got, ok := logActivityType(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("logActivityType(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// countStatusErrors underpins the dashboard's error tile. Only osquery's
// ERROR severity (2) counts — warnings are routine and would keep the tile
// permanently lit.
func TestCountStatusErrorsCountsOnlyErrors(t *testing.T) {
	batch := []byte(`[
		{"severity":0,"message":"info"},
		{"severity":1,"message":"warning"},
		{"severity":2,"message":"error one"},
		{"severity":2,"message":"error two"}
	]`)
	if got := countStatusErrors(batch); got != 2 {
		t.Fatalf("countStatusErrors = %d, want 2", got)
	}
}

// osquery sends severity as a bare int or a quoted string depending on
// version and logger plugin; types.StringInt absorbs both and the count must
// not depend on which one arrived.
func TestCountStatusErrorsAcceptsStringSeverity(t *testing.T) {
	batch := []byte(`[{"severity":"2","message":"error"},{"severity":"0","message":"info"}]`)
	if got := countStatusErrors(batch); got != 1 {
		t.Fatalf("countStatusErrors = %d, want 1", got)
	}
}

// A malformed or empty batch must yield zero rather than an error: this feeds
// a counter, and losing a count beats failing log ingestion.
func TestCountStatusErrorsToleratesBadInput(t *testing.T) {
	for name, batch := range map[string]string{
		"malformed":   `{"not":"an array"}`,
		"empty array": `[]`,
		"garbage":     `not json at all`,
		"null":        `null`,
	} {
		if got := countStatusErrors([]byte(batch)); got != 0 {
			t.Errorf("%s: countStatusErrors = %d, want 0", name, got)
		}
	}
}

// A batch carrying several errors advances the counter by that many, rather
// than by one per request.
func TestRecordActivityCountEmitsTheGivenCount(t *testing.T) {
	store := &recordingActivityStore{notify: make(chan struct{}, 1)}
	writer := NewActivityWriter(store, 1, time.Second, 4)
	defer writer.close()

	h := &HandlersTLS{ActivityWriter: writer}
	h.recordActivityCount("ENV-UUID", "NODE-UUID", activity.EventStatusError, 4)

	select {
	case <-store.notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for activity flush")
	}

	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := events[0]
	if got.Type != activity.EventStatusError || got.Count != 4 {
		t.Fatalf("unexpected event: %+v", got)
	}
}

// A batch with no errors must not emit an event at all, so a healthy fleet
// does not write a rollup key on every check-in.
func TestRecordActivityCountSkipsZero(t *testing.T) {
	store := &recordingActivityStore{notify: make(chan struct{}, 1)}
	writer := NewActivityWriter(store, 1, time.Second, 4)
	defer writer.close()

	h := &HandlersTLS{ActivityWriter: writer}
	h.recordActivityCount("ENV-UUID", "NODE-UUID", activity.EventStatusError, 0)

	select {
	case <-store.notify:
		t.Fatal("a zero count must not emit an event")
	case <-time.After(200 * time.Millisecond):
	}
}
