package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

type eventStats struct {
	Enabled     bool   `json:"enabled"`
	Healthy     bool   `json:"healthy"`
	Subscribers int    `json:"subscribers"`
	Dropped     uint64 `json:"dropped"`
}

type healthEvents struct {
	Status     string
	API        eventStats
	TLS        eventStats
	TLSPresent bool
}

type session struct {
	base   string
	client *http.Client
	bearer string
}

type config struct {
	apiURLs        []string
	proxyURL       string
	username       string
	password       string
	bearer         string
	env            string
	topics         []string
	connections    int
	timeout        time.Duration
	hold           time.Duration
	insecure       bool
	expectDisabled bool
	minAPIs        int
}

func main() {
	cfg, err := parseFlags()
	if err == nil {
		err = run(context.Background(), cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func parseFlags() (config, error) {
	var rawAPI, rawTopics string
	cfg := config{env: "all", connections: 8, timeout: 15 * time.Second, minAPIs: 1}
	flag.StringVar(&rawAPI, "api-url", "", "Comma-separated direct osctrl-api base URLs, one per API replica to verify")
	flag.StringVar(&cfg.proxyURL, "proxy-url", "", "Proxy/frontend base URL used for SSE smoke tests; defaults to first api-url")
	flag.StringVar(&cfg.username, "username", "", "Admin username for password login")
	flag.StringVar(&cfg.password, "password", "", "Admin password for password login")
	flag.StringVar(&cfg.bearer, "bearer-token", "", "Bearer token to use instead of password login")
	flag.StringVar(&cfg.env, "env", "all", "Event env selector")
	flag.StringVar(&rawTopics, "topics", "fleet", "Comma-separated event topics")
	flag.IntVar(&cfg.connections, "connections", 8, "Concurrent SSE streams for cleanup/load check")
	flag.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "Per-check timeout")
	flag.DurationVar(&cfg.hold, "hold", 0, "Keep streams open for this long before cleanup, useful while restarting replicas")
	flag.BoolVar(&cfg.insecure, "insecure", false, "Skip TLS certificate verification")
	flag.BoolVar(&cfg.expectDisabled, "expect-disabled", false, "Verify rollback state: features.events=false and /events unavailable")
	flag.IntVar(&cfg.minAPIs, "min-apis", 1, "Minimum api-url entries required")
	flag.Parse()

	var err error
	cfg.apiURLs, err = parseList(rawAPI)
	if err != nil {
		return cfg, fmt.Errorf("api-url: %w", err)
	}
	cfg.topics, err = parseList(rawTopics)
	if err != nil {
		return cfg, fmt.Errorf("topics: %w", err)
	}
	if cfg.proxyURL == "" {
		cfg.proxyURL = cfg.apiURLs[0]
	}
	if cfg.connections < 1 {
		return cfg, errors.New("connections must be positive")
	}
	if len(cfg.apiURLs) < cfg.minAPIs {
		return cfg, fmt.Errorf("need at least %d api-url value(s), got %d", cfg.minAPIs, len(cfg.apiURLs))
	}
	if (cfg.username == "") != (cfg.password == "") {
		return cfg, errors.New("username and password must be provided together")
	}
	return cfg, nil
}

func parseList(raw string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty list")
	}
	return out, nil
}

func run(parent context.Context, cfg config) error {
	ctx, cancel := context.WithTimeout(parent, cfg.timeout)
	defer cancel()

	apis, err := buildSessions(cfg.apiURLs, cfg)
	if err != nil {
		return err
	}
	proxy, err := buildSession(cfg.proxyURL, cfg)
	if err != nil {
		return err
	}
	all := append([]*session{}, apis...)
	all = append(all, proxy)
	for _, s := range all {
		if err := s.login(ctx, cfg); err != nil {
			return err
		}
	}

	if cfg.expectDisabled {
		for _, s := range all {
			if err := s.expectFeaturesDisabled(ctx); err != nil {
				return err
			}
		}
		if err := proxy.expectEventsUnavailable(ctx, cfg); err != nil {
			return err
		}
		fmt.Println("PASS rollback: live updates disabled and event stream unavailable")
		return nil
	}

	for _, s := range all {
		if err := s.expectFeatures(ctx, cfg.topics); err != nil {
			return err
		}
	}
	if _, err := proxy.openReadyStream(ctx, cfg); err != nil {
		return fmt.Errorf("proxy streaming smoke: %w", err)
	}
	fmt.Println("PASS proxy streaming: stream.ready received")

	baseline, err := subscriberTotal(ctx, apis)
	if err != nil {
		return err
	}
	streams, err := openStreams(ctx, proxy, cfg, cfg.connections)
	if err != nil {
		return err
	}
	defer closeStreams(streams)
	if err := waitSubscribers(ctx, apis, baseline+cfg.connections, true); err != nil {
		return err
	}
	if cfg.hold > 0 {
		fmt.Printf("HOLD streams open for %s\n", cfg.hold)
		select {
		case <-ctx.Done():
			return fmt.Errorf("hold interrupted before cleanup: %w", ctx.Err())
		case <-time.After(cfg.hold):
		}
	}
	closeStreams(streams)
	if err := waitSubscribers(ctx, apis, baseline, false); err != nil {
		return err
	}
	if err := expectHealthyEvents(ctx, apis); err != nil {
		return err
	}
	fmt.Printf("PASS cleanup/load: %d stream(s) opened and cleaned up\n", cfg.connections)
	fmt.Println("PASS health: live-update counters healthy")
	return nil
}

func buildSessions(raw []string, cfg config) ([]*session, error) {
	out := make([]*session, 0, len(raw))
	for _, base := range raw {
		s, err := buildSession(base, cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func buildSession(base string, cfg config) (*session, error) {
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", base, err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &session{base: strings.TrimRight(base, "/"), bearer: cfg.bearer, client: &http.Client{Jar: jar, Transport: transport}}, nil
}

func (s *session) login(ctx context.Context, cfg config) error {
	if cfg.username == "" || cfg.bearer != "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"username": cfg.username, "password": cfg.password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("/api/v1/login"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s login: %w", s.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s login: status %d %s", s.base, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (s *session) expectFeatures(ctx context.Context, topics []string) error {
	var features struct {
		Events      bool     `json:"events"`
		EventTopics []string `json:"event_topics"`
	}
	if err := s.getJSON(ctx, "/api/v1/features", &features); err != nil {
		return err
	}
	if !features.Events {
		return fmt.Errorf("%s features.events=false", s.base)
	}
	for _, topic := range topics {
		if !contains(features.EventTopics, topic) {
			return fmt.Errorf("%s missing event topic %q in %v", s.base, topic, features.EventTopics)
		}
	}
	return nil
}

func (s *session) expectFeaturesDisabled(ctx context.Context) error {
	var features struct {
		Events bool `json:"events"`
	}
	if err := s.getJSON(ctx, "/api/v1/features", &features); err != nil {
		return err
	}
	if features.Events {
		return fmt.Errorf("%s features.events=true, want false", s.base)
	}
	return nil
}

func (s *session) expectEventsUnavailable(ctx context.Context, cfg config) error {
	req, err := s.newRequest(ctx, http.MethodGet, eventPath(cfg), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%s rollback event stream status = %d, want 404", s.base, resp.StatusCode)
	}
	return nil
}

func (s *session) openReadyStream(ctx context.Context, cfg config) (*http.Response, error) {
	req, err := s.newRequest(ctx, http.MethodGet, eventPath(cfg), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("%s events status %d %s", s.base, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	reader := bufio.NewReader(resp.Body)
	for {
		frame, err := reader.ReadString('\n')
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		if strings.TrimSpace(frame) == "" {
			continue
		}
		for !strings.HasSuffix(frame, "\n\n") {
			line, err := reader.ReadString('\n')
			if err != nil {
				resp.Body.Close()
				return nil, err
			}
			frame += line
			if strings.HasSuffix(frame, "\r\n\r\n") {
				break
			}
		}
		event, _, err := parseSSEFrame(frame)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		if event == "stream.ready" {
			return resp, nil
		}
	}
}

func openStreams(ctx context.Context, s *session, cfg config, n int) ([]*http.Response, error) {
	streams := make([]*http.Response, 0, n)
	for i := 0; i < n; i++ {
		resp, err := s.openReadyStream(ctx, cfg)
		if err != nil {
			closeStreams(streams)
			return nil, err
		}
		streams = append(streams, resp)
	}
	return streams, nil
}

func closeStreams(streams []*http.Response) {
	for _, resp := range streams {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
}

func subscriberTotal(ctx context.Context, apis []*session) (int, error) {
	total := 0
	for _, s := range apis {
		events, err := s.healthEvents(ctx)
		if err != nil {
			return 0, err
		}
		total += events.API.Subscribers
	}
	return total, nil
}

func waitSubscribers(ctx context.Context, apis []*session, want int, atLeast bool) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		got, err := subscriberTotal(ctx, apis)
		if err == nil && (atLeast && got >= want || !atLeast && got <= want) {
			return nil
		}
		select {
		case <-ctx.Done():
			if atLeast {
				return fmt.Errorf("subscribers did not reach %d before timeout", want)
			}
			return fmt.Errorf("subscribers did not return to %d before timeout", want)
		case <-ticker.C:
		}
	}
}

func expectHealthyEvents(ctx context.Context, apis []*session) error {
	for _, s := range apis {
		events, err := s.healthEvents(ctx)
		if err != nil {
			return err
		}
		if events.Status != "operational" {
			return fmt.Errorf("%s live updates health = %s", s.base, events.Status)
		}
		if events.API.Dropped != 0 {
			return fmt.Errorf("%s API event drops = %d", s.base, events.API.Dropped)
		}
		if events.TLSPresent && events.TLS.Dropped != 0 {
			return fmt.Errorf("%s TLS event drops = %d", s.base, events.TLS.Dropped)
		}
	}
	return nil
}

func (s *session) healthEvents(ctx context.Context) (healthEvents, error) {
	req, err := s.newRequest(ctx, http.MethodGet, "/api/v1/health/status", nil)
	if err != nil {
		return healthEvents{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return healthEvents{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return healthEvents{}, fmt.Errorf("%s health status %d %s", s.base, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return parseHealthEvents(data)
}

func (s *session) getJSON(ctx context.Context, path string, out any) error {
	req, err := s.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s status %d %s", s.base, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s decode: %w", s.base, path, err)
	}
	return nil
}

func (s *session) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.url(path), body)
	if err != nil {
		return nil, err
	}
	if s.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.bearer)
	}
	return req, nil
}

func (s *session) url(path string) string { return s.base + path }

func eventPath(cfg config) string {
	params := url.Values{"env": {cfg.env}}
	for _, topic := range cfg.topics {
		params.Add("topic", topic)
	}
	return "/api/v1/events?" + params.Encode()
}

func parseSSEFrame(frame string) (string, map[string]any, error) {
	event := "message"
	data := make([]string, 0, 1)
	for _, line := range strings.Split(strings.ReplaceAll(frame, "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		if key == "event" {
			event = value
		}
		if key == "data" {
			data = append(data, value)
		}
	}
	if len(data) == 0 {
		return event, nil, errors.New("SSE frame has no data")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.Join(data, "\n")), &payload); err != nil {
		return event, nil, err
	}
	return event, payload, nil
}

func parseHealthEvents(body []byte) (healthEvents, error) {
	var resp struct {
		Components []struct {
			ID      string `json:"id"`
			Status  string `json:"status"`
			Details struct {
				API *eventStats `json:"api"`
				TLS *eventStats `json:"tls"`
			} `json:"details"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return healthEvents{}, err
	}
	for _, component := range resp.Components {
		if component.ID != "events" {
			continue
		}
		out := healthEvents{Status: component.Status}
		if component.Details.API != nil {
			out.API = *component.Details.API
		}
		if component.Details.TLS != nil {
			out.TLS = *component.Details.TLS
			out.TLSPresent = true
		}
		return out, nil
	}
	return healthEvents{}, errors.New("events component not found in health response")
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
