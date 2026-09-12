package events

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
)

func localBus() *Bus { return &Bus{healthy: true, subs: make(map[*subscription]struct{})} }

func TestSubscriptionIsolationAndReset(t *testing.T) {
	b := localBus()
	queries, closeQueries, err := b.Subscribe("alice", 1, []string{Queries})
	require.NoError(t, err)
	defer closeQueries()
	carves, closeCarves, err := b.Subscribe("alice", 1, []string{Carves})
	require.NoError(t, err)
	defer closeCarves()
	other, closeOther, err := b.Subscribe("bob", 2, []string{Queries})
	require.NoError(t, err)
	defer closeOther()
	hint := Hint{EnvironmentID: 1, Topic: Queries, Name: "q"}
	b.deliver(hint)
	require.Equal(t, hint, <-queries)
	select {
	case <-carves:
		t.Fatal("query leaked to carve subscription")
	default:
	}
	select {
	case <-other:
		t.Fatal("query leaked across environments")
	default:
	}
	b.reset(false)
	_, open := <-queries
	require.False(t, open)
	_, _, err = b.Subscribe("alice", 1, []string{Queries})
	require.ErrorIs(t, err, ErrUnavailable)
	b.reset(true)
	_, cancel, err := b.Subscribe("alice", 1, []string{Queries})
	require.NoError(t, err)
	cancel()
}

func TestConnectionLimitAndSlowSubscriber(t *testing.T) {
	b := localBus()
	for i := 0; i < maxUserConnections; i++ {
		_, close, err := b.Subscribe("alice", 1, []string{Queries})
		require.NoError(t, err)
		defer close()
	}
	_, _, err := b.Subscribe("alice", 1, []string{Queries})
	require.ErrorIs(t, err, ErrLimit)
	for i := 0; i <= queueSize; i++ {
		b.deliver(Hint{EnvironmentID: 1, Topic: Queries, Name: "q"})
	}
	require.Empty(t, b.subs)
	require.EqualValues(t, maxUserConnections, b.Dropped())
}

func TestConcurrentSubscriptionCleanup(t *testing.T) {
	b := localBus()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, cancel, err := b.Subscribe(fmt.Sprint(i), 1, []string{Queries})
			if err != nil {
				return
			}
			b.deliver(Hint{EnvironmentID: 1, Topic: Queries, Name: "q"})
			cancel()
			cancel()
		}(i)
	}
	wg.Wait()
	require.Empty(t, b.subs)
}

func TestConfigurationAndHintValidation(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:1"})
	defer client.Close()
	for _, namespace := range []string{"", "a:b", "a*", "../deployment"} {
		_, err := New(client, namespace, false)
		require.Error(t, err)
	}
	for _, hint := range []Hint{
		{EnvironmentID: 0, Topic: Queries, Name: "q"},
		{EnvironmentID: 1, Topic: "console", Name: "q"},
		{EnvironmentID: 1, Topic: Queries, Name: ""},
		{EnvironmentID: 1, Topic: Queries, Name: "q", Change: "other"},
		{EnvironmentID: 1, Topic: Queries, Name: "q", Change: ChangeFiles},
	} {
		require.False(t, hint.Valid())
	}
}

// Uses the same opt-in disposable Redis convention as query-dispatch tests.
func TestRedisFanoutAndNamespaceIsolation(t *testing.T) {
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to a disposable Redis instance")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())
	namespace := fmt.Sprintf("events-test-%d", time.Now().UnixNano())
	newBus := func(namespace string, consume bool) *Bus {
		b, err := New(client, namespace, consume)
		require.NoError(t, err)
		t.Cleanup(b.Close)
		return b
	}
	writer := newBus(namespace, false)
	first := newBus(namespace, true)
	second := newBus(namespace, true)
	isolated := newBus(namespace+"-other", true)
	subscribe := func(b *Bus) <-chan Hint {
		var ch <-chan Hint
		require.Eventually(t, func() bool {
			var cancel func()
			var err error
			ch, cancel, err = b.Subscribe("alice", 1, []string{Queries})
			if err == nil {
				t.Cleanup(cancel)
			}
			return err == nil
		}, 3*time.Second, 10*time.Millisecond)
		return ch
	}
	a, b, other := subscribe(first), subscribe(second), subscribe(isolated)
	want := Hint{EnvironmentID: 1, Topic: Queries, Name: "q"}
	writer.Publish(want)
	for _, ch := range []<-chan Hint{a, b} {
		select {
		case got := <-ch:
			require.Equal(t, want, got)
		case <-time.After(3 * time.Second):
			t.Fatal("missing fanout")
		}
	}
	select {
	case <-other:
		t.Fatal("cross-namespace event")
	case <-time.After(50 * time.Millisecond):
	}
	first.Close()
	_, open := <-a
	require.False(t, open)
	writer.Publish(want)
	select {
	case got := <-b:
		require.Equal(t, want, got)
	case <-time.After(3 * time.Second):
		t.Fatal("closing one replica affected another")
	}
}

func TestRedisReconnectResetsExistingStreams(t *testing.T) {
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to a disposable Redis instance")
	}
	name := fmt.Sprintf("events-reconnect-%d", time.Now().UnixNano())
	client := redis.NewClient(&redis.Options{Addr: addr, OnConnect: func(ctx context.Context, conn *redis.Conn) error { return conn.ClientSetName(ctx, name).Err() }})
	defer client.Close()
	b, err := New(client, name, true)
	require.NoError(t, err)
	defer b.Close()
	var stream <-chan Hint
	require.Eventually(t, func() bool {
		var cancel func()
		stream, cancel, err = b.Subscribe("alice", 1, []string{Queries})
		if err == nil {
			t.Cleanup(cancel)
		}
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	clients, err := client.ClientList(context.Background()).Result()
	require.NoError(t, err)
	id := ""
	for _, line := range strings.Split(clients, "\n") {
		fields := make(map[string]string)
		for _, field := range strings.Fields(line) {
			key, value, ok := strings.Cut(field, "=")
			if ok {
				fields[key] = value
			}
		}
		if fields["name"] == name && strings.Contains(fields["flags"], "P") {
			id = fields["id"]
			break
		}
	}
	require.NotEmpty(t, id)
	// Disconnect only this test's subscription, never other Redis clients.
	require.NoError(t, client.Do(context.Background(), "CLIENT", "KILL", "ID", id).Err())
	select {
	case _, open := <-stream:
		require.False(t, open)
	case <-time.After(3 * time.Second):
		t.Fatal("stale browser stream remained open")
	}
	require.Eventually(t, func() bool {
		var cancel func()
		stream, cancel, err = b.Subscribe("alice", 1, []string{Queries})
		if err == nil {
			t.Cleanup(cancel)
		}
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	want := Hint{EnvironmentID: 1, Topic: Queries, Name: "after-reconnect"}
	b.Publish(want)
	select {
	case got := <-stream:
		require.Equal(t, want, got)
	case <-time.After(3 * time.Second):
		t.Fatal("reconnected stream did not receive changes")
	}
}
