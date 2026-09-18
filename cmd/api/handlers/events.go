package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
	Change          string `json:"change,omitempty"`
	SessionID       uint   `json:"session_id,omitempty"`
	ResourceID      uint   `json:"resource_id,omitempty"`
}

// EventsHandler streams authorized query/carve/session/alert/fleet invalidations.
// @Summary Subscribe to resource change notifications
// @Description Best-effort SSE invalidation hints. No replay; refetch REST snapshots after stream.ready and retain polling. Requires the corresponding environment query/carve/admin permissions. Session-scoped console and file_explorer topics require console_session or file_explorer_session respectively. Alerts may use env=all. service_commands and fleet require super-admin permissions and env=all.
// @Tags Events
// @Produce text/event-stream json
// @Param env query string true "Environment name or UUID; use all only with topic=alerts, topic=service_commands, or topic=fleet"
// @Param topic query []string true "Topics: queries, carves, console, file_explorer, alerts, service_commands, fleet" collectionFormat(multi)
// @Param console_session query int false "Console session id required when subscribing to topic=console"
// @Param file_explorer_session query int false "File explorer session id required when subscribing to topic=file_explorer"
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
	if err != nil || len(selectors["env"]) != 1 || len(selectors["env"][0]) == 0 || len(selectors["env"][0]) > 256 || len(selectors["topic"]) == 0 || len(selectors["topic"]) > 7 {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	for key := range selectors {
		if key != "env" && key != "topic" && key != "console_session" && key != "file_explorer_session" {
			apiErrorResponse(w, "invalid event selector", http.StatusBadRequest, nil)
			return
		}
	}
	topics := selectors["topic"]
	globalOnly := true
	for _, topic := range topics {
		if topic != events.Queries && topic != events.Carves && topic != events.Console && topic != events.FileExplorer && topic != events.Alerts && topic != events.ServiceCommands && topic != events.Fleet {
			apiErrorResponse(w, "invalid event topic", http.StatusBadRequest, nil)
			return
		}
		if topic != events.Alerts && topic != events.ServiceCommands && topic != events.Fleet {
			globalOnly = false
		}
	}
	consoleSessionID, ok := eventOptionalUintSelector(selectors, "console_session")
	if !ok {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	fileExplorerSessionID, ok := eventOptionalUintSelector(selectors, "file_explorer_session")
	if !ok {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	if eventTopicSelected(topics, events.Console) != (consoleSessionID != 0) || eventTopicSelected(topics, events.FileExplorer) != (fileExplorerSessionID != 0) {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	envSelector := selectors.Get("env")
	if (eventTopicSelected(topics, events.ServiceCommands) || eventTopicSelected(topics, events.Fleet)) && envSelector != "all" {
		apiErrorResponse(w, "invalid event subscription", http.StatusBadRequest, nil)
		return
	}
	environmentID := uint(0)
	environmentUUID := "all"
	if !globalOnly || envSelector != "all" {
		env, err := h.Envs.Get(envSelector)
		if err != nil {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, nil)
			return
		}
		environmentID = env.ID
		environmentUUID = env.UUID
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	username := ctx[ctxUser]
	authorized := func() bool {
		if !h.EventsAuthenticate(r) {
			return false
		}
		// A deleted environment must stop an existing environment-scoped subscription too.
		if environmentID != 0 {
			current, err := h.Envs.GetByID(environmentID)
			if err != nil || current.UUID != environmentUUID {
				return false
			}
		}
		for _, topic := range topics {
			if topic == events.Alerts || topic == events.ServiceCommands || topic == events.Fleet {
				if !h.Users.CheckPermissions(username, users.AdminLevel, users.NoEnvironment) {
					return false
				}
				continue
			}
			level := users.QueryLevel
			if topic == events.Carves {
				level = users.CarveLevel
			}
			if topic == events.Console || topic == events.FileExplorer {
				level = users.AdminLevel
			}
			if !h.Users.CheckPermissions(username, level, environmentUUID) {
				return false
			}
		}
		if consoleSessionID != 0 && !h.authorizedConsoleEventSession(username, environmentID, consoleSessionID) {
			return false
		}
		if fileExplorerSessionID != 0 && !h.authorizedFileExplorerEventSession(username, environmentID, fileExplorerSessionID) {
			return false
		}
		return true
	}
	if !authorized() {
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	stream, unsubscribe, err := h.Events.Subscribe(username, environmentID, topics)
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
	if err := write("stream.ready", map[string]any{"environment_uuid": environmentUUID, "topics": topics, "replay": false}); err != nil {
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
			if !eventHintAllowed(hint, consoleSessionID, fileExplorerSessionID) {
				continue
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
				change := hint.Change
				if change == "" {
					change = events.ChangeMetadata
				}
				if err := write("resource.changed", ResourceChanged{SchemaVersion: 1, EnvironmentUUID: environmentUUID, Topic: hint.Topic, Name: hint.Name, Change: change, SessionID: hint.SessionID, ResourceID: hint.ResourceID}); err != nil {
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

func eventOptionalUintSelector(selectors url.Values, key string) (uint, bool) {
	values := selectors[key]
	if len(values) == 0 {
		return 0, true
	}
	if len(values) != 1 || values[0] == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(values[0], 10, 32)
	if err != nil || value == 0 {
		return 0, false
	}
	return uint(value), true
}

func eventTopicSelected(topics []string, want string) bool {
	for _, topic := range topics {
		if topic == want {
			return true
		}
	}
	return false
}

func eventHintAllowed(hint events.Hint, consoleSessionID, fileExplorerSessionID uint) bool {
	switch hint.Topic {
	case events.Console:
		return consoleSessionID != 0 && hint.SessionID == consoleSessionID
	case events.FileExplorer:
		return fileExplorerSessionID != 0 && hint.SessionID == fileExplorerSessionID
	default:
		return true
	}
}

func (h *HandlersApi) authorizedConsoleEventSession(username string, environmentID, sessionID uint) bool {
	if h.Console == nil {
		return false
	}
	session, err := h.Console.GetSession(sessionID)
	return err == nil && session.Active && session.EnvironmentID == environmentID && session.Creator == username
}

func (h *HandlersApi) authorizedFileExplorerEventSession(username string, environmentID, sessionID uint) bool {
	if h.FileExplorer == nil {
		return false
	}
	session, err := h.FileExplorer.GetSession(sessionID)
	return err == nil && session.Active && session.EnvironmentID == environmentID && session.Creator == username
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
