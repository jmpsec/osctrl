package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

const (
	// HTTPFormatJSON sends the payload as-is with a JSON content type.
	HTTPFormatJSON = "json"
	// HTTPFormatNDJSON splits array payloads into newline-delimited JSON
	// objects, one per line. Non-array payloads are sent as a single line.
	HTTPFormatNDJSON = "ndjson"
	// HTTPFormatRaw sends the bytes verbatim using the configured
	// content type, with no re-serialization.
	HTTPFormatRaw = "raw"
)

// httpDefaultTimeout caps a single HTTP request so an unresponsive
// endpoint cannot stall the log ingestion path indefinitely.
const httpDefaultTimeout = 30 * time.Second

// LoggerHTTP is a generic HTTP log sink. It forwards osquery log
// payloads to an arbitrary HTTP/HTTPS endpoint with configurable
// method, headers, and serialization format. Unlike Splunk or Graylog,
// it does not impose a vendor-specific envelope; operators choose
// whether metadata is wrapped via IncludeMetadata.
type LoggerHTTP struct {
	Configuration config.HTTPLogger
	client        *http.Client
	headers       map[string]string
	Enabled       bool
}

// CreateLoggerHTTP initializes a generic HTTP logger from the given
// configuration. The HTTP client is reused across calls so connection
// pooling is effective.
func CreateLoggerHTTP(cfg *config.HTTPLogger) (*LoggerHTTP, error) {
	if cfg == nil {
		cfg = &config.HTTPLogger{}
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodPost
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = HTTPFormatJSON
	}
	contentType := strings.TrimSpace(cfg.ContentType)
	if contentType == "" {
		switch format {
		case HTTPFormatNDJSON:
			contentType = "application/x-ndjson"
		case HTTPFormatRaw:
			contentType = "application/octet-stream"
		default:
			contentType = "application/json"
		}
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = httpDefaultTimeout
	}
	headers := make(map[string]string, len(cfg.Headers)+1)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = contentType
	}
	l := &LoggerHTTP{
		Configuration: config.HTTPLogger{
			URL:             cfg.URL,
			Method:          method,
			Headers:         cfg.Headers,
			Format:          format,
			ContentType:     contentType,
			TimeoutSeconds:  cfg.TimeoutSeconds,
			IncludeMetadata: cfg.IncludeMetadata,
		},
		client:  &http.Client{Timeout: timeout},
		headers: headers,
		Enabled: true,
	}
	return l, nil
}

// Settings is a no-op for the HTTP logger; all configuration is carried
// in the config struct. The method exists to satisfy the exporter
// convention used by the registry builder.
func (l *LoggerHTTP) Settings(mgr *settings.Settings) {
	log.Info().Msg("Setting HTTP logging settings")
}

// Close releases the HTTP client transport so pooled connections are
// not leaked across hot reloads.
func (l *LoggerHTTP) Close() error {
	if l.client != nil {
		l.client.CloseIdleConnections()
	}
	return nil
}

// httpEnvelope wraps a raw osquery event with osctrl metadata when
// IncludeMetadata is enabled.
type httpEnvelope struct {
	Environment string          `json:"environment"`
	UUID        string          `json:"uuid"`
	LogType     string          `json:"log_type"`
	Timestamp   int64           `json:"timestamp"`
	Event       json.RawMessage `json:"event"`
}

// Send serializes and transmits the osquery payload to the configured
// HTTP endpoint. The format and metadata wrapping are controlled by
// the configuration.
func (l *LoggerHTTP) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if l.Configuration.URL == "" {
		return
	}
	body, err := l.encode(logType, data, environment, uuid)
	if err != nil {
		log.Err(err).Str("type", logType).Msg("http sink: encode error")
		return
	}
	if debug {
		log.Debug().Msgf("http sink: sending %d bytes (%s) to %s", body.Len(), logType, l.Configuration.URL)
	}
	req, err := http.NewRequest(l.Configuration.Method, l.Configuration.URL, body)
	if err != nil {
		log.Err(err).Msg("http sink: build request")
		return
	}
	for k, v := range l.headers {
		req.Header.Set(k, v)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		log.Err(err).Msg("http sink: send request")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Warn().
			Int("status", resp.StatusCode).
			Str("type", logType).
			Bytes("body", respBody).
			Msg("http sink: non-2xx response")
	}
	if debug {
		log.Debug().Msgf("http sink: response %d", resp.StatusCode)
	}
}

// encode produces the request body according to the configured format
// and metadata preference.
func (l *LoggerHTTP) encode(logType string, data []byte, environment, uuid string) (*bytes.Buffer, error) {
	if !l.Configuration.IncludeMetadata {
		if l.Configuration.Format == HTTPFormatNDJSON {
			return l.encodeNDJSON(data, nil)
		}
		return bytes.NewBuffer(data), nil
	}
	// Metadata wrapping: split array payloads into individual events,
	// envelope each one, then re-serialize according to format.
	var events []json.RawMessage
	if logType == types.QueryLog {
		events = []json.RawMessage{data}
	} else {
		if err := json.Unmarshal(data, &events); err != nil {
			events = []json.RawMessage{data}
		}
	}
	now := time.Now().Unix()
	envelopes := make([]httpEnvelope, 0, len(events))
	for _, ev := range events {
		envelopes = append(envelopes, httpEnvelope{
			Environment: environment,
			UUID:        uuid,
			LogType:     logType,
			Timestamp:   now,
			Event:       ev,
		})
	}
	switch l.Configuration.Format {
	case HTTPFormatNDJSON:
		return l.encodeNDJSON(nil, envelopes)
	case HTTPFormatRaw:
		return bytes.NewBuffer(data), nil
	default:
		out, err := json.Marshal(envelopes)
		if err != nil {
			return nil, fmt.Errorf("marshal http envelopes: %w", err)
		}
		return bytes.NewBuffer(out), nil
	}
}

// encodeNDJSON writes events as newline-delimited JSON. When raw is
// non-nil and envelopes is nil, it splits the raw array payload into
// individual lines. When envelopes is non-nil, each envelope is written
// as one line.
func (l *LoggerHTTP) encodeNDJSON(raw []byte, envelopes []httpEnvelope) (*bytes.Buffer, error) {
	buf := bytes.NewBuffer(nil)
	if envelopes != nil {
		for _, e := range envelopes {
			line, err := json.Marshal(e)
			if err != nil {
				return nil, fmt.Errorf("marshal ndjson line: %w", err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		buf.Write(raw)
		if !bytes.HasSuffix(raw, []byte{'\n'}) {
			buf.WriteByte('\n')
		}
		return buf, nil
	}
	for _, item := range items {
		buf.Write(item)
		buf.WriteByte('\n')
	}
	return buf, nil
}
