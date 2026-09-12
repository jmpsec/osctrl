package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/jmpsec/osctrl/pkg/users"
)

// ResourceChanged is a cache invalidation hint, never an operation result.
type ResourceChanged struct {
	SchemaVersion   int    `json:"schema_version"`
	EnvironmentUUID string `json:"environment_uuid"`
	Topic           string `json:"topic"`
	Name            string `json:"name"`
}

// EventsHandler streams authorized query/carve invalidations.
// @Summary Subscribe to resource change notifications
// @Description Best-effort SSE invalidation hints. No replay; refetch REST snapshots after stream.ready and retain polling. Requires the corresponding environment query/carve permissions.
// @Tags Events
// @Produce text/event-stream json
// @Param env query string true "Environment name or UUID"
// @Param topic query []string true "Topics: queries, carves" collectionFormat(multi)
// @Success 200 {string} string "SSE stream: stream.ready, resource.changed, auth.expired"
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 401 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 429 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/events [get]
func (h *HandlersApi) EventsHandler(w http.ResponseWriter, r *http.Request) {
	if h.Events == nil || h.EventsAuthenticate == nil {
		apiErrorResponse(w, "events unavailable", http.StatusNotFound, nil)
		return
	}
	if !eventOriginAllowed(r) {
		apiErrorResponse(w, "origin not allowed", http.StatusForbidden, nil)
		return
	}
	if len(r.URL.RawQuery) > 2048 {
		apiErrorResponse(w, "event selectors too large", http.StatusBadRequest, nil)
		return
	}
	selectors, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(selectors["env"]) != 1 || len(selectors["env"][0]) == 0 || len(selectors["env"][0]) > 256 || len(selectors["topic"]) == 0 || len(selectors["topic"]) > 2 {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	for key := range selectors {
		if key != "env" && key != "topic" {
			apiErrorResponse(w, "invalid event selector", http.StatusBadRequest, nil)
			return
		}
	}
	topics := selectors["topic"]
	for _, topic := range topics {
		if topic != events.Queries && topic != events.Carves {
			apiErrorResponse(w, "invalid event topic", http.StatusBadRequest, nil)
			return
		}
	}
	env, err := h.Envs.Get(selectors.Get("env"))
	if err != nil {
		apiErrorResponse(w, "environment not found", http.StatusNotFound, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	username := ctx[ctxUser]
	authorized := func() bool {
		if !h.EventsAuthenticate(r) {
			return false
		}
		// A deleted environment must stop an existing subscription too.
		current, err := h.Envs.GetByID(env.ID)
		if err != nil || current.UUID != env.UUID {
			return false
		}
		for _, topic := range topics {
			level := users.QueryLevel
			if topic == events.Carves {
				level = users.CarveLevel
			}
			if !h.Users.CheckPermissions(username, level, env.UUID) {
				return false
			}
		}
		return true
	}
	if !authorized() {
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	stream, unsubscribe, err := h.Events.Subscribe(username, env.ID, topics)
	if err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, events.ErrLimit) {
			code = http.StatusTooManyRequests
		}
		apiErrorResponse(w, "event stream unavailable", code, nil)
		return
	}
	defer unsubscribe()
	controller := http.NewResponseController(w)
	// Require bounded writes rather than silently running without deadlines.
	if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		apiErrorResponse(w, "streaming unsupported", http.StatusServiceUnavailable, nil)
		return
	}
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(event string, value any) error {
		if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return err
		}
		return controller.Flush()
	}
	if err := write("stream.ready", map[string]any{"environment_uuid": env.UUID, "topics": topics, "replay": false}); err != nil {
		return
	}
	flush := time.NewTicker(250 * time.Millisecond)
	defer flush.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	pending := make(map[events.Hint]struct{})
	for {
		select {
		case <-r.Context().Done():
			return
		case hint, ok := <-stream:
			if !ok {
				return
			}
			pending[hint] = struct{}{}
			// Bounded memory even if thousands of distinct queries change.
			if len(pending) > 64 {
				return
			}
		case <-flush.C:
			if len(pending) == 0 {
				continue
			}
			if !authorized() {
				_ = write("auth.expired", struct{}{})
				return
			}
			for hint := range pending {
				if err := write("resource.changed", ResourceChanged{1, env.UUID, hint.Topic, hint.Name}); err != nil {
					return
				}
				delete(pending, hint)
			}
		case <-heartbeat.C:
			if !authorized() {
				_ = write("auth.expired", struct{}{})
				return
			}
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

func eventOriginAllowed(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // Same-origin EventSource may omit Origin.
	u, err := url.Parse(origin)
	return err == nil && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && strings.EqualFold(u.Host, r.Host) && (u.Scheme == "https" || (u.Scheme == "http" && r.TLS == nil))
}
