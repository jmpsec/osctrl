package cache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
)

type redisJSONTestValue struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func TestRedisJSONCacheRoundTrip(t *testing.T) {
	client, store := newRedisJSONTestClient(t)
	cache := NewRedisJSONCache[redisJSONTestValue](client, "test:json")

	ctx := context.Background()
	require.NoError(t, cache.Set(ctx, "alpha", redisJSONTestValue{Name: "alpha", Enabled: true}, time.Minute))

	got, ok, err := cache.Get(ctx, "alpha")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, redisJSONTestValue{Name: "alpha", Enabled: true}, got)
	require.Equal(t, time.Minute, store.expireFor("test:json:alpha"))
}

func TestRedisJSONCacheDelete(t *testing.T) {
	client, _ := newRedisJSONTestClient(t)
	cache := NewRedisJSONCache[redisJSONTestValue](client, "test:json")

	ctx := context.Background()
	require.NoError(t, cache.Set(ctx, "alpha", redisJSONTestValue{Name: "alpha"}, time.Minute))
	require.NoError(t, cache.Delete(ctx, "alpha"))

	_, ok, err := cache.Get(ctx, "alpha")
	require.NoError(t, err)
	require.False(t, ok)
}

func newRedisJSONTestClient(t *testing.T) (*redis.Client, *redisJSONFakeStore) {
	t.Helper()

	store := &redisJSONFakeStore{
		values:  make(map[string][]byte),
		expires: make(map[string]time.Duration),
	}
	client := redis.NewClient(&redis.Options{
		Addr:     "fake-redis",
		PoolSize: 1,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			go serveRedisJSONFake(serverConn, store)
			return clientConn, nil
		},
	})

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client, store
}

type redisJSONFakeStore struct {
	mu      sync.Mutex
	values  map[string][]byte
	expires map[string]time.Duration
}

func serveRedisJSONFake(conn net.Conn, store *redisJSONFakeStore) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readRedisJSONRESPArray(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_, _ = conn.Write([]byte("-ERR read failed\r\n"))
			}
			return
		}
		if len(args) == 0 {
			_, _ = conn.Write([]byte("-ERR empty command\r\n"))
			return
		}

		if err := handleRedisJSONFakeCommand(conn, store, args); err != nil {
			_, _ = conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
			return
		}
	}
}

func handleRedisJSONFakeCommand(conn net.Conn, store *redisJSONFakeStore, args []string) error {
	switch strings.ToUpper(args[0]) {
	case "GET":
		if len(args) != 2 {
			return fmt.Errorf("unexpected GET args: %v", args)
		}
		value, ok := store.get(args[1])
		if !ok {
			_, err := conn.Write([]byte("$-1\r\n"))
			return err
		}
		_, err := fmt.Fprintf(conn, "$%d\r\n", len(value))
		if err != nil {
			return err
		}
		_, err = conn.Write(append(value, []byte("\r\n")...))
		return err

	case "SET":
		if len(args) != 3 && len(args) != 5 {
			return fmt.Errorf("unexpected SET args: %v", args)
		}
		var ttl time.Duration
		if len(args) == 5 {
			if strings.ToUpper(args[3]) != "EX" {
				return fmt.Errorf("unexpected SET expiration args: %v", args)
			}
			seconds, err := strconv.Atoi(args[4])
			if err != nil {
				return err
			}
			ttl = time.Duration(seconds) * time.Second
		}
		store.set(args[1], []byte(args[2]), ttl)
		_, err := conn.Write([]byte("+OK\r\n"))
		return err

	case "DEL":
		for _, key := range args[1:] {
			store.delete(key)
		}
		_, err := fmt.Fprintf(conn, ":%d\r\n", len(args)-1)
		return err

	case "PING":
		_, err := conn.Write([]byte("+PONG\r\n"))
		return err

	default:
		return fmt.Errorf("unsupported command %q", args[0])
	}
}

func readRedisJSONRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected array, got %q", line)
	}
	count, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimSuffix(strings.TrimSuffix(header, "\n"), "\r")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", header)
		}
		size, err := strconv.Atoi(strings.TrimPrefix(header, "$"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func (s *redisJSONFakeStore) set(key string, value []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values[key] = append([]byte(nil), value...)
	if ttl > 0 {
		s.expires[key] = ttl
	}
}

func (s *redisJSONFakeStore) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.values[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (s *redisJSONFakeStore) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.values, key)
	delete(s.expires, key)
}

func (s *redisJSONFakeStore) expireFor(key string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.expires[key]
}
