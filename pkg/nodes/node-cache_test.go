package nodes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	redis "github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// fakeRedis serves GET, SET (with EX/NX) and PING over RESP, enough for
// RedisJSONCache.
type fakeRedis struct {
	mu   sync.Mutex
	vals map[string]string
}

func newFakeRedisClient(t *testing.T, f *fakeRedis) *redis.Client {
	t.Helper()
	c := redis.NewClient(&redis.Options{Addr: "fake", Dialer: func(context.Context, string, string) (net.Conn, error) {
		srv, cli := net.Pipe()
		go f.serve(srv)
		return cli, nil
	}})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESP(r)
		if err != nil {
			return
		}
		f.mu.Lock()
		var reply string
		switch strings.ToUpper(args[0]) {
		case "PING":
			reply = "+PONG\r\n"
		case "GET":
			if v, ok := f.vals[args[1]]; ok {
				reply = fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
			} else {
				reply = "$-1\r\n"
			}
		case "SET":
			nx := strings.EqualFold(args[len(args)-1], "NX")
			if _, exists := f.vals[args[1]]; nx && exists {
				reply = "$-1\r\n"
			} else {
				f.vals[args[1]] = args[2]
				reply = "+OK\r\n"
			}
		default:
			reply = "-ERR unsupported\r\n"
		}
		f.mu.Unlock()
		if _, err := io.WriteString(conn, reply); err != nil {
			return
		}
	}
}

func readRESP(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		if _, err := r.ReadString('\n'); err != nil {
			return nil, err
		}
		v, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args[i] = strings.TrimSuffix(v, "\r\n")
	}
	return args, nil
}

// A key revoked by one process (re-enroll or delete) stops authenticating in
// another process that already cached it, and a stale refill cannot restore it.
func TestRedisNodeCacheRevocationIsShared(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	f := &fakeRedis{vals: map[string]string{}}
	api, tls := CreateNodes(db), CreateNodes(db)
	api.UseRedisCache(newFakeRedisClient(t, f))
	tls.UseRedisCache(newFakeRedisClient(t, f))

	node := OsqueryNode{UUID: "NODE-A", NodeKey: "old-key", EnvironmentID: 1}
	require.NoError(t, api.Create(&node))
	_, err = tls.GetByKey("old-key")
	require.NoError(t, err, "warm the shared cache")

	// Re-enrollment in one process rotates the key everywhere.
	require.NoError(t, api.Update(node, OsqueryNode{NodeKey: "new-key"}))
	_, err = tls.GetByKey("old-key")
	require.Error(t, err)
	got, err := tls.GetByKey("new-key")
	require.NoError(t, err)

	// A reader that loaded the row before deletion cannot re-cache it.
	require.NoError(t, api.ArchiveDelete(got))
	require.NoError(t, tls.Cache.redisCache.SetNX(context.Background(), "new-key", got, redisNodeTTL))
	_, err = tls.GetByKey("new-key")
	require.Error(t, err)
}
