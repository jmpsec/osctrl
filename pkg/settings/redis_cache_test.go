package settings

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
)

func newSettingsRedisTestClient(t *testing.T) (*redis.Client, *settingsRedisFakeStore) {
	t.Helper()

	store := &settingsRedisFakeStore{
		values:  make(map[string][]byte),
		expires: make(map[string]time.Duration),
	}
	client := redis.NewClient(&redis.Options{
		Addr:     "fake-redis",
		PoolSize: 1,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			go serveSettingsRedisFake(serverConn, store)
			return clientConn, nil
		},
	})

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client, store
}

type settingsRedisFakeStore struct {
	mu      sync.Mutex
	values  map[string][]byte
	expires map[string]time.Duration
}

func serveSettingsRedisFake(conn net.Conn, store *settingsRedisFakeStore) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readSettingsRESPArray(reader)
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

		if err := handleSettingsRedisCommand(conn, store, args); err != nil {
			_, _ = conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
			return
		}
	}
}

func handleSettingsRedisCommand(conn net.Conn, store *settingsRedisFakeStore, args []string) error {
	switch strings.ToUpper(args[0]) {
	case "GET":
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
		var ttl time.Duration
		if len(args) == 5 {
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

func readSettingsRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
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

func (s *settingsRedisFakeStore) set(key string, value []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values[key] = append([]byte(nil), value...)
	if ttl > 0 {
		s.expires[key] = ttl
	}
}

func (s *settingsRedisFakeStore) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.values[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (s *settingsRedisFakeStore) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.values, key)
	delete(s.expires, key)
}
