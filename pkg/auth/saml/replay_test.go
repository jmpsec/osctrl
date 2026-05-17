package saml

import (
	"testing"
	"time"
)

func TestReplayCache_FirstSightAccepted(t *testing.T) {
	rc := newReplayCache(5 * time.Minute)
	if !rc.remember("assertion-1") {
		t.Fatal("first sighting should be accepted")
	}
}

func TestReplayCache_DuplicateRejected(t *testing.T) {
	rc := newReplayCache(5 * time.Minute)
	rc.remember("assertion-1")
	if rc.remember("assertion-1") {
		t.Fatal("duplicate within window should be rejected (replay defense S3)")
	}
}

func TestReplayCache_EmptyIDAccepted(t *testing.T) {
	rc := newReplayCache(5 * time.Minute)
	if !rc.remember("") {
		t.Fatal("empty ID should be accepted without recording")
	}
	// Calling again with empty ID still accepted — empty isn't tracked.
	if !rc.remember("") {
		t.Fatal("repeated empty ID should still be accepted")
	}
}

func TestReplayCache_ExpiredEntryReadmitted(t *testing.T) {
	// Use a 1ms window so we can trip the expiry without sleeping for
	// minutes. Sleep slightly longer than the window to guarantee
	// expiration before the second call.
	rc := newReplayCache(1 * time.Millisecond)
	rc.remember("assertion-1")
	time.Sleep(20 * time.Millisecond)
	if !rc.remember("assertion-1") {
		t.Fatal("entry past replay window should be re-admitted (sweep ran)")
	}
}

func TestReplayCache_MixedIDs(t *testing.T) {
	rc := newReplayCache(5 * time.Minute)
	ids := []string{"a", "b", "c", "d"}
	for _, id := range ids {
		if !rc.remember(id) {
			t.Fatalf("first sight of %q rejected", id)
		}
	}
	for _, id := range ids {
		if rc.remember(id) {
			t.Fatalf("duplicate %q accepted", id)
		}
	}
}
