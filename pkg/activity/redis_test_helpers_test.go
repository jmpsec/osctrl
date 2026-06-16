package activity

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

func newTestRedisClient(t *testing.T) (*redis.Client, *fakeRedisStore) {
	t.Helper()

	store := &fakeRedisStore{
		values:  make(map[string][]byte),
		expires: make(map[string]time.Duration),
	}
	client := redis.NewClient(&redis.Options{
		Addr:     "fake-redis",
		PoolSize: 1,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			go serveFakeRedis(serverConn, store)
			return clientConn, nil
		},
	})

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client, store
}

type fakeRedisStore struct {
	mu      sync.Mutex
	values  map[string][]byte
	expires map[string]time.Duration
}

func serveFakeRedis(conn net.Conn, store *fakeRedisStore) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(reader)
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

		if err := handleFakeRedisCommand(conn, store, args); err != nil {
			_, _ = conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
			return
		}
	}
}

func handleFakeRedisCommand(conn net.Conn, store *fakeRedisStore, args []string) error {
	switch strings.ToUpper(args[0]) {
	case "BITFIELD":
		if len(args) != 8 {
			return fmt.Errorf("unexpected BITFIELD args: %v", args)
		}
		key := args[1]
		offset, err := strconv.Atoi(args[6])
		if err != nil {
			return err
		}
		increment, err := strconv.Atoi(args[7])
		if err != nil {
			return err
		}

		value := store.incrByU16(key, offset, increment)
		_, err = fmt.Fprintf(conn, "*1\r\n:%d\r\n", value)
		return err

	case "EXPIRE":
		if len(args) != 3 {
			return fmt.Errorf("unexpected EXPIRE args: %v", args)
		}
		seconds, err := strconv.Atoi(args[2])
		if err != nil {
			return err
		}
		store.expire(args[1], time.Duration(seconds)*time.Second)
		_, err = conn.Write([]byte(":1\r\n"))
		return err

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

	case "PING":
		_, err := conn.Write([]byte("+PONG\r\n"))
		return err

	default:
		return fmt.Errorf("unsupported command %q", args[0])
	}
}

func (s *fakeRedisStore) incrByU16(key string, bitOffset int, increment int) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	byteOffset := bitOffset / 8
	buf := append([]byte(nil), s.values[key]...)
	if len(buf) < byteOffset+2 {
		buf = append(buf, make([]byte, byteOffset+2-len(buf))...)
	}

	current := uint16(buf[byteOffset])<<8 | uint16(buf[byteOffset+1])
	next := int(current) + increment
	if next > int(^uint16(0)) {
		next = int(^uint16(0))
	}
	if next < 0 {
		next = 0
	}

	value := uint16(next)
	buf[byteOffset] = byte(value >> 8)
	buf[byteOffset+1] = byte(value)
	s.values[key] = buf

	return value
}

func (s *fakeRedisStore) expire(key string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expires[key] = ttl
}

func (s *fakeRedisStore) expireFor(key string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.expires[key]
}

func (s *fakeRedisStore) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.values[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func readRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[0] != '*' {
		return nil, fmt.Errorf("unexpected RESP header %q", line)
	}

	count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(sizeLine) < 3 || sizeLine[0] != '$' {
			return nil, fmt.Errorf("unexpected bulk header %q", sizeLine)
		}

		size, err := strconv.Atoi(strings.TrimSpace(sizeLine[1:]))
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
