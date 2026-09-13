package alerts

import (
	"strings"
	"sync"
	"testing"

	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type recordingAlertPublisher struct {
	mu    sync.Mutex
	hints []events.Hint
}

func (p *recordingAlertPublisher) Publish(h events.Hint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hints = append(p.hints, h)
}

func (p *recordingAlertPublisher) snapshot() []events.Hint {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]events.Hint, len(p.hints))
	copy(out, p.hints)
	return out
}

func TestManagerPublishesAlertInvalidations(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	publisher := &recordingAlertPublisher{}
	mgr := NewManager(db)
	mgr.Events = publisher

	rule, err := mgr.CreateRule(AlertRule{Name: "sudoers", Source: SourceResultLog, MatchType: MatchTypeSubstring, MatchValue: "/etc/sudoers", Enabled: true})
	require.NoError(t, err)
	channel, err := mgr.CreateChannel(AlertChannel{Name: "soc", Type: ChannelWebhook, Config: `{"url":"https://example.com/hook"}`, Enabled: true})
	require.NoError(t, err)
	require.NoError(t, mgr.RecordHistory(AlertHistory{RuleID: rule.ID, RuleName: rule.Name, ChannelID: channel.ID, ChannelName: channel.Name, Environment: "prod"}))

	require.Equal(t, []events.Hint{
		{EnvironmentID: NoEnvironmentID, Topic: events.Alerts, Name: events.ChangeRules, Change: events.ChangeRules},
		{EnvironmentID: NoEnvironmentID, Topic: events.Alerts, Name: events.ChangeChannels, Change: events.ChangeChannels},
		{EnvironmentID: NoEnvironmentID, Topic: events.Alerts, Name: events.ChangeHistory, Change: events.ChangeHistory},
	}, publisher.snapshot())
}
