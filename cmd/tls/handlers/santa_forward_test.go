package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// santaSink records what the Santa handler sends to the log sinks.
type santaSink struct {
	fail  bool
	types []string
	data  [][]byte
	uuids []string
}

func (s *santaSink) Name() string    { return "test" }
func (s *santaSink) IsEnabled() bool { return true }
func (s *santaSink) Close() error    { return nil }
func (s *santaSink) Export(logType string, data []byte, p logging.ExportParams) error {
	if s.fail {
		return errors.New("sink down")
	}
	s.types = append(s.types, logType)
	s.data = append(s.data, data)
	s.uuids = append(s.uuids, p.UUID)
	return nil
}

// santaMatcher records the events handed to the alert rules.
type santaMatcher struct {
	logging.AlertMatcher
	envID  uint
	node   string
	events []map[string]string
}

func (m *santaMatcher) MatchSantaEvents(envID uint, _ string, nodeUUID string, events []map[string]string) {
	m.envID, m.node, m.events = envID, nodeUUID, events
}

func santaUpload(t *testing.T) []byte {
	t.Helper()
	body, err := protojson.Marshal(&syncv1.EventUploadRequest{Events: []*syncv1.Event{{
		FileSha256:    strings.Repeat("ab", 32),
		FilePath:      "/tmp",
		FileName:      "evil",
		ExecutingUser: "alice",
		Decision:      syncv1.Decision_BLOCK_BINARY,
		TeamId:        "EQHXZ8M8AV",
	}}})
	require.NoError(t, err)
	return body
}

func TestSantaEventUploadForwardsToSinksAndAlerts(t *testing.T) {
	f := newSantaFixture(t)
	sink, matcher := &santaSink{}, &santaMatcher{}
	f.h.Logs = logging.CreateLoggerTLSWith(map[uint]*logging.MultiExporter{0: logging.NewMultiExporter(sink)}, nodes.CreateNodes(f.db), nil)
	f.h.Logs.Alerts = matcher
	node := strings.ToUpper(santaMachineID)

	// Preflight registers the machine; events are refused before it.
	require.Equal(t, http.StatusOK, f.post(santaEnvUUID, "preflight", santaMachineID, f.token, []byte(`{}`)).Code)
	w := f.post(santaEnvUUID, "eventupload", santaMachineID, f.token, santaUpload(t))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.Equal(t, []string{types.SantaLog}, sink.types)
	require.Equal(t, []string{node}, sink.uuids)
	var sent []santa.Event
	require.NoError(t, json.Unmarshal(sink.data[0], &sent), "sinks need a JSON array")
	require.Len(t, sent, 1)
	require.Equal(t, "BLOCK_BINARY", sent[0].Decision)
	require.NotZero(t, sent[0].ID)

	require.Equal(t, f.env.ID, matcher.envID)
	require.Equal(t, node, matcher.node)
	require.Len(t, matcher.events, 1)
	require.Equal(t, "BLOCK_BINARY", matcher.events[0]["decision"])
	require.Equal(t, "EQHXZ8M8AV", matcher.events[0]["team_id"])

	// A failing sink does not fail the upload: the events are stored, and a
	// retry would store them twice.
	sink.fail = true
	w = f.post(santaEnvUUID, "eventupload", santaMachineID, f.token, santaUpload(t))
	require.Equal(t, http.StatusOK, w.Code)
	var stored int64
	require.NoError(t, f.db.Model(&santa.Event{}).Count(&stored).Error)
	require.EqualValues(t, 2, stored)

	// An empty upload sends nothing.
	sink.fail, sink.types = false, nil
	require.Equal(t, http.StatusOK, f.post(santaEnvUUID, "eventupload", santaMachineID, f.token, []byte(`{}`)).Code)
	require.Empty(t, sink.types)
}

// Without a logger (as in older fixtures) the upload still works.
func TestSantaEventUploadWithoutLogger(t *testing.T) {
	f := newSantaFixture(t)
	require.Equal(t, http.StatusOK, f.post(santaEnvUUID, "preflight", santaMachineID, f.token, []byte(`{}`)).Code)
	require.Equal(t, http.StatusOK, f.post(santaEnvUUID, "eventupload", santaMachineID, f.token, santaUpload(t)).Code)
}

// An osquery node cannot forge Santa events into the sinks through the
// osquery log endpoint.
func TestLogHandlerRejectsSantaLogType(t *testing.T) {
	f := newSantaFixture(t)
	sink := &santaSink{}
	f.h.Logs = logging.CreateLoggerTLSWith(map[uint]*logging.MultiExporter{0: logging.NewMultiExporter(sink)}, nodes.CreateNodes(f.db), nil)
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", strings.ToUpper(santaMachineID)).Update("node_key", "key-a").Error)
	r := httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{"node_key":"key-a","log_type":"santa","data":[{"decision":"BLOCK_BINARY"}]}`))
	r.SetPathValue("env", santaEnvUUID)
	w := httptest.NewRecorder()
	f.h.LogHandler(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, sink.types)
}
