package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ErrChannelDisabled marks a channel the operator turned off. The
// dispatcher skips these without treating them as failures.
var ErrChannelDisabled = errors.New("alert channel disabled")

// dispatch.go — channel fan-out implementing DispatchSink.
//
// For each hit the dispatcher resolves the hit's channel IDs to
// alert_channels rows, builds (and caches) a ChannelSender per channel,
// delivers to each independently, and writes one alert_history row per
// successfully delivered channel. A failing channel never prevents the
// others from being notified.
//
// Sender cache: channel configs are static between reloads, so built
// senders are memoized by channel ID + config hash. Reload swaps the
// whole cache (copy-on-write), matching the rule snapshot pattern.

// Dispatcher fans hits out to configured channels.
type Dispatcher struct {
	mgr *Manager

	mu      sync.RWMutex
	senders map[uint]cachedSender

	// now is overridable in tests.
	now func() time.Time
}

// cachedSender pairs a built sender with the config it was built from.
type cachedSender struct {
	config   string
	sender   ChannelSender
	channel  AlertChannel
	buildErr error
}

// NewDispatcher builds a channel dispatcher over the alert manager.
func NewDispatcher(mgr *Manager) *Dispatcher {
	return &Dispatcher{
		mgr:     mgr,
		senders: map[uint]cachedSender{},
		now:     time.Now,
	}
}

// RefreshChannel drops the cached sender for one channel so the next
// dispatch rebuilds it from the current row.
func (d *Dispatcher) RefreshChannel(id uint) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.senders, id)
}

// Reset drops all cached senders (full reload).
func (d *Dispatcher) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.senders = map[uint]cachedSender{}
}

// senderFor resolves the cached sender for a channel ID, building it
// when missing or stale.
func (d *Dispatcher) senderFor(id uint) (ChannelSender, AlertChannel, error) {
	row, err := d.mgr.GetChannel(id)
	if err != nil {
		return nil, AlertChannel{}, err
	}
	d.mu.RLock()
	cached, ok := d.senders[id]
	d.mu.RUnlock()
	if ok && cached.config == row.Config && cached.buildErr == nil {
		return cached.sender, row, nil
	}
	spec, ok := ChannelRegistry[normalizeChannelType(row.Type)]
	if !ok {
		err := fmt.Errorf("%w: %q", ErrInvalidChannelType, row.Type)
		d.storeBuild(id, row, nil, err)
		return nil, row, err
	}
	if !row.Enabled {
		err := fmt.Errorf("channel %q: %w", row.Name, ErrChannelDisabled)
		d.storeBuild(id, row, nil, err)
		return nil, row, err
	}
	decoded, err := spec.Decode(json.RawMessage(row.Config))
	if err != nil {
		d.storeBuild(id, row, nil, err)
		return nil, row, err
	}
	sender, err := spec.Build(decoded)
	if err != nil {
		d.storeBuild(id, row, nil, err)
		return nil, row, err
	}
	d.storeBuild(id, row, sender, nil)
	return sender, row, nil
}

func (d *Dispatcher) storeBuild(id uint, row AlertChannel, sender ChannelSender, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.senders[id] = cachedSender{config: row.Config, sender: sender, channel: row, buildErr: err}
}

// Dispatch delivers the hit to every referenced channel. Channels that
// are disabled, mis-typed, or missing are skipped without counting as
// failures — an operator disabling a channel is a choice, not an
// outage. Real delivery errors are per-channel: one dead webhook does
// not block the email. Returns an error only when at least one
// delivery was attempted and every one of them failed (so the worker
// can retry the claim). Zero usable channels is a no-op success.
func (d *Dispatcher) Dispatch(ctx context.Context, h Hit) error {
	// honor ctx cancellation between channels
	if err := ctx.Err(); err != nil {
		return err
	}
	var attempts, delivered int
	for _, id := range h.Channels {
		sender, row, err := d.senderFor(id)
		if err != nil {
			if errors.Is(err, ErrChannelDisabled) || errors.Is(err, ErrChannelNotFound) || errors.Is(err, ErrInvalidChannelType) {
				// Operator intent or dangling reference — skip
				// silently; not a delivery failure.
				continue
			}
			// Config decode / build problems are worth surfacing but
			// also not delivery failures.
			log.Warn().Err(err).Uint("channel_id", id).Msg("alert channel unusable")
			continue
		}
		attempts++
		if err := sender.Send(h); err != nil {
			log.Err(err).
				Uint("channel_id", id).
				Str("channel", row.Name).
				Uint("rule_id", h.RuleID).
				Msg("alert channel delivery failed")
			continue
		}
		delivered++
		// Per-channel history row (auditable "who was notified").
		if err := d.mgr.RecordHistory(AlertHistory{
			RuleID:      h.RuleID,
			RuleName:    h.RuleName,
			ChannelID:   row.ID,
			ChannelName: row.Name,
			Environment: h.Environment,
			NodeUUID:    h.NodeUUID,
			Entity:      h.Entity,
			Detail:      h.Detail,
		}); err != nil {
			log.Err(err).Msg("recording alert history failed")
		}
	}
	if attempts > 0 && delivered == 0 {
		return fmt.Errorf("alert %q: all %d channel delivery attempt(s) failed", h.RuleName, attempts)
	}
	return nil
}
