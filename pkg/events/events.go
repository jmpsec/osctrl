// Package events distributes best-effort resource invalidation hints. REST and
// the underlying stores remain authoritative; hints are neither replayable nor
// proof that a background operation or result export succeeded.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	redis "github.com/go-redis/redis/v8"
)

var (
	ErrUnavailable   = errors.New("event transport unavailable")
	ErrLimit         = errors.New("event connection limit reached")
	namespacePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

const (
	Queries            = "queries"
	Carves             = "carves"
	maxConnections     = 1000
	maxUserConnections = 8
	queueSize          = 64
)

// Hint is an internal routing envelope. Numeric environment IDs never leave
// the API, which resolves and authorizes the requested environment separately.
type Hint struct {
	EnvironmentID uint   `json:"environment_id"`
	Topic         string `json:"topic"`
	Name          string `json:"name"`
}

func (h Hint) Valid() bool {
	return h.EnvironmentID != 0 && (h.Topic == Queries || h.Topic == Carves) && len(h.Name) > 0 && len(h.Name) <= 256
}

type Publisher interface{ Publish(Hint) }

type Subscriber interface {
	Subscribe(string, uint, []string) (<-chan Hint, func(), error)
}

type subscription struct {
	user          string
	environmentID uint
	topics        map[string]bool
	ch            chan Hint
}

// Bus owns one Redis subscription per API process and bounded subscriber queues.
// A TLS process constructs a publish-only Bus. Call Close before HTTP draining.
type Bus struct {
	client   *redis.Client
	channel  string
	ctx      context.Context
	cancel   context.CancelFunc
	pubsub   *redis.PubSub
	queue    chan Hint
	wg       sync.WaitGroup
	once     sync.Once
	mu       sync.Mutex
	healthy  bool
	lastRead time.Time
	closed   bool
	subs     map[*subscription]struct{}
	dropped  atomic.Uint64
}

func New(client *redis.Client, namespace string, consume bool) (*Bus, error) {
	if client == nil || !namespacePattern.MatchString(namespace) {
		return nil, errors.New("events require Redis and a namespace of 1-64 letters, digits, underscores or hyphens")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bus{client: client, channel: "osctrl:" + namespace + ":events:v1", ctx: ctx, cancel: cancel, queue: make(chan Hint, 1024), subs: make(map[*subscription]struct{})}
	b.wg.Add(1)
	go b.publishLoop()
	if consume {
		b.pubsub = client.Subscribe(ctx, b.channel)
		b.wg.Add(2)
		go b.receiveLoop()
		go b.healthLoop()
	}
	return b, nil
}

func (b *Bus) Publish(h Hint) {
	if !h.Valid() {
		return
	}
	select {
	case <-b.ctx.Done():
	case b.queue <- h:
	default:
		b.dropped.Add(1)
	}
}

// Dropped includes failed publication and slow-subscriber disconnections.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

func (b *Bus) publishLoop() {
	defer b.wg.Done()
	for {
		select {
		case <-b.ctx.Done():
			return
		case h := <-b.queue:
			data, err := json.Marshal(h)
			if err != nil {
				b.dropped.Add(1)
				continue
			}
			ctx, cancel := context.WithTimeout(b.ctx, time.Second)
			err = b.client.Publish(ctx, b.channel, data).Err()
			cancel()
			if err != nil {
				b.dropped.Add(1)
			}
		}
	}
}

func (b *Bus) receiveLoop() {
	defer b.wg.Done()
	for b.ctx.Err() == nil {
		message, err := b.pubsub.ReceiveTimeout(b.ctx, 20*time.Second)
		if err != nil {
			b.reset(false)
			select {
			case <-b.ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		b.mu.Lock()
		b.lastRead = time.Now()
		b.mu.Unlock()
		switch message := message.(type) {
		case *redis.Subscription:
			// A reconnect may have missed events. Force every browser to
			// obtain a fresh snapshot, including after a brief Redis outage.
			b.reset(message.Kind == "subscribe")
		case *redis.Message:
			if len(message.Payload) > 4096 {
				continue
			}
			var hint Hint
			if json.Unmarshal([]byte(message.Payload), &hint) == nil && hint.Valid() {
				b.deliver(hint)
			}
		case *redis.Pong:
			b.mu.Lock()
			if !b.closed {
				b.healthy = true
			}
			b.mu.Unlock()
		}
	}
}

func (b *Bus) healthLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			stale := !b.lastRead.IsZero() && time.Since(b.lastRead) > 30*time.Second
			b.mu.Unlock()
			if stale {
				b.reset(false)
			}
			ctx, cancel := context.WithTimeout(b.ctx, 2*time.Second)
			err := b.pubsub.Ping(ctx)
			cancel()
			if err != nil {
				b.reset(false)
			}
		}
	}
}

func (b *Bus) reset(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		close(s.ch)
		delete(b.subs, s)
	}
	b.healthy = healthy && !b.closed
}

func (b *Bus) deliver(h Hint) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		if s.environmentID != h.EnvironmentID || !s.topics[h.Topic] {
			continue
		}
		select {
		case s.ch <- h:
		default:
			close(s.ch)
			delete(b.subs, s)
			b.dropped.Add(1)
		}
	}
}

func (b *Bus) Subscribe(user string, environmentID uint, topics []string) (<-chan Hint, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.healthy {
		return nil, nil, ErrUnavailable
	}
	n := 0
	for s := range b.subs {
		if s.user == user {
			n++
		}
	}
	if len(b.subs) >= maxConnections || n >= maxUserConnections {
		return nil, nil, ErrLimit
	}
	s := &subscription{user: user, environmentID: environmentID, topics: make(map[string]bool), ch: make(chan Hint, queueSize)}
	for _, topic := range topics {
		s.topics[topic] = true
	}
	b.subs[s] = struct{}{}
	return s.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
	}, nil
}

func (b *Bus) Close() {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		b.cancel()
		if b.pubsub != nil {
			_ = b.pubsub.Close()
		}
		b.reset(false)
		b.wg.Wait()
	})
}
