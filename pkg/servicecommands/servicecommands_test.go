package servicecommands

import (
	"bytes"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupServiceCommandsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&ServiceCommand{}))
	return db
}

func TestRequestRestartCreatesPendingCommand(t *testing.T) {
	m := &Manager{DB: setupServiceCommandsDB(t)}

	cmd, err := m.RequestRestart(config.ServiceTLS, "alice", "127.0.0.1", time.Minute)
	require.NoError(t, err)

	require.NotEmpty(t, cmd.CommandID)
	require.Equal(t, config.ServiceTLS, cmd.TargetService)
	require.Equal(t, ActionRestart, cmd.Action)
	require.Equal(t, StatusPending, cmd.Status(time.Now()))
}

func TestConsumeNextConsumesCommandOnce(t *testing.T) {
	m := &Manager{DB: setupServiceCommandsDB(t)}
	created, err := m.RequestRestart(config.ServiceTLS, "alice", "127.0.0.1", time.Minute)
	require.NoError(t, err)

	consumed, ok, err := m.ConsumeNext(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, created.CommandID, consumed.CommandID)
	require.Equal(t, StatusConsumed, consumed.Status(time.Now()))

	_, ok, err = m.ConsumeNext(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestConsumeNextSkipsExpiredCommands(t *testing.T) {
	m := &Manager{DB: setupServiceCommandsDB(t)}
	created, err := m.RequestRestart(config.ServiceTLS, "alice", "127.0.0.1", time.Nanosecond)
	require.NoError(t, err)

	now := created.ExpiresAt.Add(time.Second)
	_, ok, err := m.ConsumeNext(config.ServiceTLS, "osctrl-tls", now)
	require.NoError(t, err)
	require.False(t, ok)

	stored, err := m.Get(created.CommandID)
	require.NoError(t, err)
	require.Equal(t, StatusExpired, stored.Status(now))
}

func TestConsumeNextDoesNotLogRecordNotFoundWhenIdle(t *testing.T) {
	var logs bytes.Buffer
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.New(log.New(&logs, "", 0), logger.Config{LogLevel: logger.Info}),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&ServiceCommand{}))
	m := &Manager{DB: db}

	_, ok, err := m.ConsumeNext(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.False(t, ok)
	require.NotContains(t, logs.String(), "record not found")
}

func TestMarkRecoveredUpdatesConsumedCommands(t *testing.T) {
	m := &Manager{DB: setupServiceCommandsDB(t)}
	created, err := m.RequestRestart(config.ServiceTLS, "alice", "127.0.0.1", time.Minute)
	require.NoError(t, err)
	_, ok, err := m.ConsumeNext(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.True(t, ok)

	n, err := m.MarkRecovered(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	stored, err := m.Get(created.CommandID)
	require.NoError(t, err)
	require.Equal(t, StatusRecovered, stored.Status(time.Now()))
	require.NotNil(t, stored.RecoveredAt)
}

type recordingServiceCommandPublisher struct {
	mu    sync.Mutex
	hints []events.Hint
}

func (p *recordingServiceCommandPublisher) Publish(h events.Hint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hints = append(p.hints, h)
}

func (p *recordingServiceCommandPublisher) snapshot() []events.Hint {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]events.Hint, len(p.hints))
	copy(out, p.hints)
	return out
}

func TestServiceCommandsPublishStatusInvalidations(t *testing.T) {
	publisher := &recordingServiceCommandPublisher{}
	m := &Manager{DB: setupServiceCommandsDB(t), Events: publisher}
	now := time.Now()

	created, err := m.RequestRestart(config.ServiceTLS, "alice", "127.0.0.1", time.Minute)
	require.NoError(t, err)
	_, ok, err := m.ConsumeNext(config.ServiceTLS, "osctrl-tls", now)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = m.MarkRecovered(config.ServiceTLS, "osctrl-tls", now)
	require.NoError(t, err)

	require.Equal(t, []events.Hint{
		{EnvironmentID: 0, Topic: events.ServiceCommands, Name: created.CommandID, Change: StatusPending},
		{EnvironmentID: 0, Topic: events.ServiceCommands, Name: created.CommandID, Change: StatusConsumed},
		{EnvironmentID: 0, Topic: events.ServiceCommands, Name: created.CommandID, Change: StatusRecovered},
	}, publisher.snapshot())
}
