package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/config"
)

func probeHandler(t *testing.T, opts ...HandlersOption) *HandlersApi {
	t.Helper()
	opts = append([]HandlersOption{WithDebugHTTP(&config.YAMLConfigurationDebug{})}, opts...)
	return CreateHandlersApi(opts...)
}

func TestLivezHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rr := httptest.NewRecorder()
	probeHandler(t).LivezHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestReadyzHandlerRequiresDatabase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	probeHandler(t).ReadyzHandler(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestReadyzHandlerRequiresRedis(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	probeHandler(t, WithDB(db)).ReadyzHandler(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestReadyzHandlerFailsOnDegradedDatabase(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	probeHandler(t, WithDB(db), WithDBHealth(&fakeDegradedReader{degraded: true})).ReadyzHandler(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestReadyzHandlerSucceedsWithDatabaseAndRedis(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("+PONG\r\n"))
			}()
		}
	}()
	redisManager := &cache.RedisManager{Client: redis.NewClient(&redis.Options{Addr: listener.Addr().String()})}
	t.Cleanup(func() { _ = redisManager.Client.Close() })

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	probeHandler(t, WithDB(db), WithRedis(redisManager)).ReadyzHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
