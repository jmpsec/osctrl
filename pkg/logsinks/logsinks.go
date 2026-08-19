// Package logsinks persists per-environment osquery log sink configurations
// to the database. Each row is one sink instance (Splunk, Kafka, S3, DB,
// stdout, …) with a JSON-encoded config blob whose shape is determined by
// the sink Type and validated against the Registry.
//
// osctrl-tls reads these rows at boot and whenever it consumes a
// reload_log_sinks service command, building a per-environment exporter
// fan-out. Rows with EnvironmentID=0 are the global fallback used by any
// environment that has no rows of its own. Rows with EnvironmentID != 0
// override the global set for that environment.
//
// The YAML logger: section remains the seed source on first boot;
// once an operator edits a sink through the API (Source="db") the YAML
// value is ignored for that sink until the DB row is deleted.
package logsinks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SourceService marks a row seeded from the resolved service
// configuration — flags, environment variables, or YAML, whichever the
// operator used. The seed is a one-time create-if-missing bootstrap;
// once a row exists it is never overwritten by a later boot.
const SourceService = "service"

// SourceDB marks a row that has been edited or created through the API.
const SourceDB = "db"

// SourceYAML is retained for backwards compatibility with rows seeded
// by older versions that used "yaml" as the source value. New seeds
// use SourceService. Reads treat both as non-DB-edited.
const SourceYAML = "yaml"

// NoEnvironmentID is the sentinel for global (non-env-scoped) sink rows.
// Mirrors settings.NoEnvironmentID / serviceconfig.NoEnvironmentID so
// callers can pass the same constant regardless of package.
const NoEnvironmentID uint = 0

// LogSink stores one osquery log destination for one environment (or
// global when EnvironmentID is NoEnvironmentID). The Config field is a
// JSON-encoded blob whose shape is determined by Type and validated
// against the Registry.
type LogSink struct {
	gorm.Model
	Name          string `gorm:"uniqueIndex:idx_log_sinks_unique"`
	EnvironmentID uint   `gorm:"uniqueIndex:idx_log_sinks_unique"`
	Type          string `gorm:"index"`
	Enabled       bool
	Order         int
	Config        string `gorm:"type:text"`
	Source        string // "yaml" (seeded) or "db" (operator-edited)
	Info          string
}

// LogSinksManager manages the log_sinks table.
type LogSinksManager struct {
	DB *gorm.DB
}

// NewLogSinksManager initializes the manager and auto-migrates the
// log_sinks table.
func NewLogSinksManager(backend *gorm.DB) *LogSinksManager {
	m := &LogSinksManager{DB: backend}
	if err := backend.AutoMigrate(&LogSink{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (log_sinks): %v", err)
	}
	return m
}

// FieldType is the input kind the frontend should render for a field.
type FieldType string

const (
	FieldString   FieldType = "string"
	FieldInteger  FieldType = "integer"
	FieldBoolean  FieldType = "boolean"
	FieldSelect   FieldType = "select"
	FieldPassword FieldType = "password" // string input masked by the SPA
)

// FieldSpec describes one configurable field of a sink type. The schema
// is declarative so the frontend can render a typed form without shipping
// a per-type component for every sink.
type FieldSpec struct {
	// Name is the JSON key inside the Config blob. Nested keys use dot
	// notation, e.g. "sasl.mechanism".
	Name string
	// Label is the human-facing label shown in the form.
	Label string
	// Type selects the input control.
	Type FieldType
	// Required marks the field as mandatory.
	Required bool
	// Secret marks the field as credential-bearing. The API redacts
	// secret fields in read responses unless reveal=1 is passed; the
	// SPA renders them as password inputs. Secret fields are also
	// listed in SinkSpec.SecretFields for the redaction code path.
	Secret bool
	// Placeholder is shown when the field is empty.
	Placeholder string
	// Help is a one-line description shown under the input.
	Help string
	// Options is the list of allowed values for FieldSelect.
	Options []string
	// Default is the value used when the field is absent on create.
	Default any
}

// SinkSpec describes one supported sink type in the Registry.
type SinkSpec struct {
	Type        string
	Description string
	// HasSecret indicates the Config JSON contains credential fields.
	// When true, the API redacts SecretFields in read responses unless
	// the caller passes reveal=true.
	HasSecret bool
	// SecretFields lists the JSON keys inside Config that hold secrets.
	SecretFields []string
	// Fields is the typed form schema the SPA renders. May be empty
	// (e.g. none, stdout) — the SPA then shows no config fields.
	Fields []FieldSpec
	// Decode unmarshals a raw JSON Config into the typed config struct
	// the sink implementation expects (e.g. *config.SplunkLogger).
	Decode func(json.RawMessage) (any, error)
	// Build instantiates a DataExporter from a decoded config struct.
	Build func(any, *settings.Settings) (logging.DataExporter, error)
}

// Registry maps each config.Logging* type to its SinkSpec. This is the
// single source of truth for what sink types exist and how each is
// configured. Adding a new sink type means: implement the exporter in
// pkg/logging, add the config struct to pkg/config, and add a SinkSpec
// here.
var Registry = map[string]SinkSpec{
	config.LoggingNone: {
		Type:        config.LoggingNone,
		Description: "Discard logs. No destination.",
		HasSecret:   false,
		Decode: func(raw json.RawMessage) (any, error) {
			// none has no config; accept and ignore any object.
			return struct{}{}, nil
		},
		Build: func(_ any, smgr *settings.Settings) (logging.DataExporter, error) {
			n, err := logging.CreateLoggerNone()
			if err != nil {
				return nil, err
			}
			n.Settings(smgr)
			return n, nil
		},
	},
	config.LoggingStdout: {
		Type:        config.LoggingStdout,
		Description: "Write logs to stdout.",
		HasSecret:   false,
		Decode: func(raw json.RawMessage) (any, error) {
			return struct{}{}, nil
		},
		Build: func(_ any, smgr *settings.Settings) (logging.DataExporter, error) {
			s, err := logging.CreateLoggerStdout()
			if err != nil {
				return nil, err
			}
			s.Settings(smgr)
			return s, nil
		},
	},
	config.LoggingFile: {
		Type:        config.LoggingFile,
		Description: "Rotating local file logger.",
		HasSecret:   false,
		Fields: []FieldSpec{
			{Name: "filePath", Label: "File path", Type: FieldString, Required: true, Placeholder: "/var/log/osquery.log", Help: "Absolute path to the log file."},
			{Name: "maxSize", Label: "Max size (MB)", Type: FieldInteger, Default: 100, Help: "Rotate after this size in MB."},
			{Name: "maxBackups", Label: "Max backups", Type: FieldInteger, Default: 3, Help: "Number of rotated files to keep."},
			{Name: "maxAge", Label: "Max age (days)", Type: FieldInteger, Default: 28, Help: "Days to retain rotated files."},
			{Name: "compress", Label: "Compress", Type: FieldBoolean, Default: false, Help: "Gzip rotated files."},
		},
		Decode: decodeTyped[config.LocalLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			f, err := logging.CreateLoggerFile(cfg.(*config.LocalLogger))
			if err != nil {
				return nil, err
			}
			f.Settings(smgr)
			return f, nil
		},
	},
	config.LoggingDB: {
		Type:         config.LoggingDB,
		Description:  "Persist logs to a SQL database (separate from or same as the primary).",
		HasSecret:    true,
		SecretFields: []string{"password"},
		Fields: []FieldSpec{
			{Name: "type", Label: "DB type", Type: FieldSelect, Required: true, Options: []string{"postgres", "mysql", "sqlite"}, Default: "postgres", Help: "Database backend."},
			{Name: "host", Label: "Host", Type: FieldString, Placeholder: "127.0.0.1", Help: "Database host. Ignored by sqlite."},
			{Name: "port", Label: "Port", Type: FieldInteger, Default: 5432, Help: "Database port. Defaults match PostgreSQL."},
			{Name: "name", Label: "Database name", Type: FieldString, Required: true, Placeholder: "osctrl", Help: "Database/schema name."},
			{Name: "username", Label: "Username", Type: FieldString, Placeholder: "postgres"},
			{Name: "password", Label: "Password", Type: FieldPassword, Secret: true, Placeholder: "prefer env vars/secrets in prod", Help: "Database password."},
			{Name: "sslmode", Label: "SSL mode", Type: FieldString, Placeholder: "disable", Help: "PostgreSQL SSL mode: disable, require, verify-full."},
			{Name: "maxIdleConns", Label: "Max idle conns", Type: FieldInteger, Default: 20},
			{Name: "maxOpenConns", Label: "Max open conns", Type: FieldInteger, Default: 100},
			{Name: "connMaxLifetime", Label: "Conn max lifetime (min)", Type: FieldInteger, Default: 30},
			{Name: "connRetry", Label: "Conn retry (s)", Type: FieldInteger, Default: 10, Help: "Seconds to retry at startup; 0 fails fast."},
			{Name: "filePath", Label: "SQLite file path", Type: FieldString, Placeholder: "./osctrl.db", Help: "SQLite database file path when type is sqlite."},
		},
		Decode: decodeTyped[config.YAMLConfigurationDB](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			d, err := logging.CreateLoggerDBConfig(cfg.(*config.YAMLConfigurationDB))
			if err != nil {
				return nil, err
			}
			d.Settings(smgr)
			return d, nil
		},
	},
	config.LoggingSplunk: {
		Type:         config.LoggingSplunk,
		Description:  "Splunk HTTP Event Collector (HEC).",
		HasSecret:    true,
		SecretFields: []string{"token"},
		Fields: []FieldSpec{
			{Name: "url", Label: "HEC URL", Type: FieldString, Required: true, Placeholder: "https://splunk.example.com:8088/services/collector", Help: "Splunk HTTP Event Collector endpoint."},
			{Name: "token", Label: "HEC token", Type: FieldPassword, Secret: true, Required: true, Placeholder: "prefer env vars/secrets in prod", Help: "Splunk HEC token."},
			{Name: "host", Label: "Host", Type: FieldString, Placeholder: "osctrl", Help: "Source host value attached to events."},
			{Name: "index", Label: "Index", Type: FieldString, Placeholder: "main", Help: "Splunk index name."},
		},
		Decode: decodeTyped[config.SplunkLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			s, err := logging.CreateLoggerSplunk(cfg.(*config.SplunkLogger))
			if err != nil {
				return nil, err
			}
			s.Settings(smgr)
			return s, nil
		},
	},
	config.LoggingGraylog: {
		Type:        config.LoggingGraylog,
		Description: "Graylog GELF over HTTP.",
		HasSecret:   false,
		Fields: []FieldSpec{
			{Name: "url", Label: "URL", Type: FieldString, Required: true, Placeholder: "https://graylog.example.com:12202/gelf", Help: "Graylog GELF HTTP input endpoint."},
			{Name: "host", Label: "Host", Type: FieldString, Placeholder: "osctrl", Help: "Source host value attached to messages."},
			{Name: "queries", Label: "Queries stream", Type: FieldString, Placeholder: "osquery_queries", Help: "Stream/name for distributed query logs."},
			{Name: "status", Label: "Status stream", Type: FieldString, Placeholder: "osquery_status", Help: "Stream/name for status logs."},
			{Name: "results", Label: "Results stream", Type: FieldString, Placeholder: "osquery_results", Help: "Stream/name for result logs."},
		},
		Decode: decodeTyped[config.GraylogLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			g, err := logging.CreateLoggerGraylog(cfg.(*config.GraylogLogger))
			if err != nil {
				return nil, err
			}
			g.Settings(smgr)
			return g, nil
		},
	},
	config.LoggingLogstash: {
		Type:        config.LoggingLogstash,
		Description: "Logstash over HTTP, TCP, or UDP.",
		HasSecret:   false,
		Fields: []FieldSpec{
			{Name: "host", Label: "Host", Type: FieldString, Required: true, Placeholder: "logstash.example.com"},
			{Name: "port", Label: "Port", Type: FieldString, Required: true, Placeholder: "5044", Help: "Logstash input port (string in the config)."},
			{Name: "protocol", Label: "Protocol", Type: FieldSelect, Options: []string{"http", "tcp", "udp"}, Default: "http"},
			{Name: "path", Label: "Path", Type: FieldString, Placeholder: "/osquery", Help: "Optional HTTP/TCP path depending on protocol."},
		},
		Decode: decodeTyped[config.LogstashLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			l, err := logging.CreateLoggerLogstash(cfg.(*config.LogstashLogger))
			if err != nil {
				return nil, err
			}
			l.Settings(smgr)
			return l, nil
		},
	},
	config.LoggingKinesis: {
		Type:         config.LoggingKinesis,
		Description:  "AWS Kinesis Data Streams.",
		HasSecret:    true,
		SecretFields: []string{"secretKey", "sessionToken"},
		Fields: []FieldSpec{
			{Name: "stream", Label: "Stream", Type: FieldString, Required: true, Placeholder: "osquery-logs", Help: "Kinesis stream name."},
			{Name: "region", Label: "Region", Type: FieldString, Required: true, Placeholder: "us-east-1"},
			{Name: "endpoint", Label: "Endpoint", Type: FieldString, Placeholder: "https://kinesis.us-east-1.amazonaws.com", Help: "Optional custom endpoint."},
			{Name: "accessKey", Label: "Access key ID", Type: FieldString, Placeholder: "prefer instance/task roles", Help: "Optional static access key."},
			{Name: "secretKey", Label: "Secret access key", Type: FieldPassword, Secret: true, Placeholder: "prefer instance/task roles"},
			{Name: "sessionToken", Label: "Session token", Type: FieldPassword, Secret: true, Placeholder: "optional"},
		},
		Decode: decodeTyped[config.KinesisLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			k, err := logging.CreateLoggerKinesis(cfg.(*config.KinesisLogger))
			if err != nil {
				return nil, err
			}
			k.Settings(smgr)
			return k, nil
		},
	},
	config.LoggingS3: {
		Type:         config.LoggingS3,
		Description:  "AWS S3 object storage.",
		HasSecret:    true,
		SecretFields: []string{"secretAccessKey"},
		Fields: []FieldSpec{
			{Name: "bucket", Label: "Bucket", Type: FieldString, Required: true, Placeholder: "osquery-logs", Help: "S3 bucket name for log objects."},
			{Name: "region", Label: "Region", Type: FieldString, Required: true, Placeholder: "us-east-1"},
			{Name: "accessKey", Label: "Access key ID", Type: FieldString, Placeholder: "prefer instance/task roles"},
			{Name: "secretAccessKey", Label: "Secret access key", Type: FieldPassword, Secret: true, Placeholder: "prefer instance/task roles"},
		},
		Decode: decodeTyped[config.S3Logger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			s, err := logging.CreateLoggerS3(cfg.(*config.S3Logger))
			if err != nil {
				return nil, err
			}
			s.Settings(smgr)
			return s, nil
		},
	},
	config.LoggingKafka: {
		Type:         config.LoggingKafka,
		Description:  "Apache Kafka producer.",
		HasSecret:    true,
		SecretFields: []string{"sasl.password"},
		Fields: []FieldSpec{
			{Name: "bootstrapServers", Label: "Bootstrap servers", Type: FieldString, Required: true, Placeholder: "broker1:9092,broker2:9092", Help: "Comma-separated Kafka bootstrap servers."},
			{Name: "topic", Label: "Topic", Type: FieldString, Required: true, Placeholder: "osquery-logs"},
			{Name: "sslCALocation", Label: "CA cert path", Type: FieldString, Placeholder: "/etc/ssl/certs/ca.pem", Help: "CA certificate path for TLS verification."},
			{Name: "connectionTimeout", Label: "Connection timeout", Type: FieldString, Placeholder: "5s", Help: "Go duration string, e.g. 5s, 10s, 1m."},
			{Name: "sasl.mechanism", Label: "SASL mechanism", Type: FieldSelect, Options: []string{"", "SCRAM-SHA-256", "SCRAM-SHA-512"}, Help: "SASL mechanism. Empty disables SASL."},
			{Name: "sasl.username", Label: "SASL username", Type: FieldString, Placeholder: "kafka-user"},
			{Name: "sasl.password", Label: "SASL password", Type: FieldPassword, Secret: true, Placeholder: "prefer env vars/secrets in prod"},
		},
		Decode: decodeTyped[config.KafkaLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			k, err := logging.CreateLoggerKafka(cfg.(*config.KafkaLogger))
			if err != nil {
				return nil, err
			}
			k.Settings(smgr)
			return k, nil
		},
	},
	config.LoggingElastic: {
		Type:        config.LoggingElastic,
		Description: "Elasticsearch index writer.",
		HasSecret:   false,
		Fields: []FieldSpec{
			{Name: "host", Label: "Host", Type: FieldString, Required: true, Placeholder: "elastic.example.com"},
			{Name: "port", Label: "Port", Type: FieldString, Required: true, Placeholder: "9200", Help: "Elasticsearch port (string in the config)."},
			{Name: "indexPrefix", Label: "Index prefix", Type: FieldString, Placeholder: "osquery", Help: "Prefix for generated index names."},
			{Name: "dateSeparator", Label: "Date separator", Type: FieldString, Placeholder: ".", Help: "Separator inside date suffixes, e.g. . for YYYY.MM.DD."},
			{Name: "indexSeparator", Label: "Index separator", Type: FieldString, Placeholder: "-", Help: "Separator between prefix and date suffix, e.g. - for prefix-YYYY.MM.DD."},
		},
		Decode: decodeTyped[config.ElasticLogger](),
		Build: func(cfg any, smgr *settings.Settings) (logging.DataExporter, error) {
			e, err := logging.CreateLoggerElastic(cfg.(*config.ElasticLogger))
			if err != nil {
				return nil, err
			}
			e.Settings(smgr)
			return e, nil
		},
	},
}

// SupportedTypes returns the Registry keys in a stable, sorted order, for
// API/UI discovery.
func SupportedTypes() []string {
	types := make([]string, 0, len(Registry))
	for k := range Registry {
		types = append(types, k)
	}
	// Stable order for UI dropdowns and tests.
	for i := 1; i < len(types); i++ {
		for j := i; j > 0 && types[j-1] > types[j]; j-- {
			types[j-1], types[j] = types[j], types[j-1]
		}
	}
	return types
}

// ValidateType reports whether the sink type is registered.
func ValidateType(typ string) bool {
	_, ok := Registry[typ]
	return ok
}

// decodeTyped returns a Decode func that unmarshals raw JSON into a fresh
// *T and returns it as any. The generic keeps every SinkSpec.Decode
// trivially consistent and type-safe.
func decodeTyped[T any]() func(json.RawMessage) (any, error) {
	return func(raw json.RawMessage) (any, error) {
		var t T
		if len(raw) == 0 || string(raw) == "null" {
			return &t, nil
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("decode %T: %w", t, err)
		}
		return &t, nil
	}
}

// ErrSinkNotFound is returned when a sink row is not found.
var ErrSinkNotFound = errors.New("log sink not found")

// ErrInvalidSinkType is returned when a sink type is not in the Registry.
var ErrInvalidSinkType = errors.New("invalid log sink type")

// ErrInvalidSinkConfig is returned when a sink's Config JSON is invalid
// or fails to decode into the type's config struct.
var ErrInvalidSinkConfig = errors.New("invalid log sink configuration")

// ErrTargetHasSinks is returned by Clone when the target environment
// already has sinks and overwrite is false.
var ErrTargetHasSinks = errors.New("target environment already has log sinks")

// normalizeType lower-cases and trims a sink type so callers can pass
// "Splunk" or "SPLUNK" and still hit the Registry.
func normalizeType(typ string) string {
	return strings.ToLower(strings.TrimSpace(typ))
}

// normalizeName trims surrounding whitespace from a sink name.
func normalizeName(name string) string {
	return strings.TrimSpace(name)
}

// validateConfig decodes the Config JSON against the registered type and
// returns the decoded value or an error. The decoded value is used by
// Build when constructing an exporter.
func validateConfig(typ, cfgJSON string) (any, error) {
	spec, ok := Registry[typ]
	if !ok {
		return nil, ErrInvalidSinkType
	}
	raw := json.RawMessage(cfgJSON)
	if len(raw) == 0 {
		raw = json.RawMessage(`null`)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%w: not valid JSON", ErrInvalidSinkConfig)
	}
	decoded, err := spec.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSinkConfig, err)
	}
	return decoded, nil
}

// ValidateSink returns an error if the proposed sink is invalid: unknown
// type, empty name, or Config that does not decode against the type.
func ValidateSink(name, typ, cfgJSON string) error {
	if normalizeName(name) == "" {
		return fmt.Errorf("sink name is required")
	}
	t := normalizeType(typ)
	if !ValidateType(t) {
		return fmt.Errorf("%w: %q", ErrInvalidSinkType, typ)
	}
	if _, err := validateConfig(t, cfgJSON); err != nil {
		return err
	}
	return nil
}

// Create inserts a new sink row.
func (m *LogSinksManager) Create(name, typ string, enabled bool, order int, cfgJSON string, envID uint, info string) (LogSink, error) {
	name = normalizeName(name)
	typ = normalizeType(typ)
	if err := ValidateSink(name, typ, cfgJSON); err != nil {
		return LogSink{}, err
	}
	row := LogSink{
		Name:          name,
		EnvironmentID: envID,
		Type:          typ,
		Enabled:       enabled,
		Order:         order,
		Config:        cfgJSON,
		Source:        SourceDB,
		Info:          info,
	}
	if err := m.DB.Create(&row).Error; err != nil {
		return LogSink{}, fmt.Errorf("create log sink: %w", err)
	}
	return row, nil
}

// Update replaces an existing sink row's mutable fields. Config is
// re-validated against the existing Type (Type can be changed in the
// same call as long as the new Config decodes against the new Type).
func (m *LogSinksManager) Update(id uint, name, typ string, enabled bool, order int, cfgJSON string, info string) (LogSink, error) {
	name = normalizeName(name)
	typ = normalizeType(typ)
	if err := ValidateSink(name, typ, cfgJSON); err != nil {
		return LogSink{}, err
	}
	row, err := m.Get(id)
	if err != nil {
		return LogSink{}, err
	}
	if err := m.DB.Model(&row).Updates(map[string]any{
		"name":    name,
		"type":    typ,
		"enabled": enabled,
		"order":   order,
		"config":  cfgJSON,
		"info":    info,
		"source":  SourceDB,
	}).Error; err != nil {
		return LogSink{}, fmt.Errorf("update log sink: %w", err)
	}
	return m.Get(id)
}

// Get retrieves one sink by ID.
func (m *LogSinksManager) Get(id uint) (LogSink, error) {
	var row LogSink
	if err := m.DB.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return LogSink{}, ErrSinkNotFound
		}
		return LogSink{}, err
	}
	return row, nil
}

// Delete removes a sink by ID.
func (m *LogSinksManager) Delete(id uint) error {
	res := m.DB.Delete(&LogSink{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrSinkNotFound
	}
	return nil
}

// ListByEnvironment returns all sinks for one environment (EnvironmentID
// == envID), ordered by Order then CreatedAt.
func (m *LogSinksManager) ListByEnvironment(envID uint) ([]LogSink, error) {
	var rows []LogSink
	if err := m.DB.Where("environment_id = ?", envID).
		Order("\"order\" ASC, created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// List returns sinks across all environments when envID is nil, or for
// a single environment when envID is non-nil.
func (m *LogSinksManager) List(envID *uint) ([]LogSink, error) {
	if envID == nil {
		var rows []LogSink
		if err := m.DB.Order("environment_id ASC, \"order\" ASC, created_at ASC").Find(&rows).Error; err != nil {
			return nil, err
		}
		return rows, nil
	}
	return m.ListByEnvironment(*envID)
}

// EffectiveFor returns the sinks that should be used for the given
// environment: if the environment has any rows of its own, those are
// returned (override-with-fallback); otherwise the global rows
// (EnvironmentID == NoEnvironmentID) are returned.
func (m *LogSinksManager) EffectiveFor(envID uint) ([]LogSink, error) {
	rows, err := m.ListByEnvironment(envID)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		return rows, nil
	}
	return m.ListByEnvironment(NoEnvironmentID)
}

// AllGrouped returns every sink, grouped by EnvironmentID, with the
// global key (0) included. Used by the API list endpoint and by the
// TLS boot/reload builder.
func (m *LogSinksManager) AllGrouped() (map[uint][]LogSink, error) {
	rows, err := m.List(nil)
	if err != nil {
		return nil, err
	}
	out := make(map[uint][]LogSink)
	for _, r := range rows {
		out[r.EnvironmentID] = append(out[r.EnvironmentID], r)
	}
	return out, nil
}

// CloneEnvironment copies all sinks from sourceEnvID to targetEnvID. If
// overwrite is false and the target already has any sinks,
// ErrTargetHasSinks is returned. If overwrite is true, the target's
// existing sinks are hard-deleted first. New sink names are suffixed
// with " (clone of env N)" when the source is non-global, or
// " (clone of global)" otherwise, so uniqueIndex on Name is preserved.
func (m *LogSinksManager) CloneEnvironment(sourceEnvID, targetEnvID uint, overwrite bool) ([]LogSink, error) {
	if sourceEnvID == targetEnvID {
		return nil, fmt.Errorf("source and target environment must differ")
	}
	srcRows, err := m.ListByEnvironment(sourceEnvID)
	if err != nil {
		return nil, fmt.Errorf("list source sinks: %w", err)
	}
	if len(srcRows) == 0 {
		return nil, fmt.Errorf("source environment has no log sinks")
	}
	tgtRows, err := m.ListByEnvironment(targetEnvID)
	if err != nil {
		return nil, fmt.Errorf("list target sinks: %w", err)
	}
	if len(tgtRows) > 0 && !overwrite {
		return nil, ErrTargetHasSinks
	}

	suffix := " (clone of global)"
	if sourceEnvID != NoEnvironmentID {
		suffix = fmt.Sprintf(" (clone of env %d)", sourceEnvID)
	}

	err = m.DB.Transaction(func(tx *gorm.DB) error {
		if len(tgtRows) > 0 {
			if err := tx.Unscoped().Where("environment_id = ?", targetEnvID).Delete(&LogSink{}).Error; err != nil {
				return fmt.Errorf("clear target sinks: %w", err)
			}
		}
		for _, r := range srcRows {
			newRow := LogSink{
				Name:          r.Name + suffix,
				EnvironmentID: targetEnvID,
				Type:          r.Type,
				Enabled:       r.Enabled,
				Order:         r.Order,
				Config:        r.Config,
				Source:        SourceDB,
				Info:          r.Info,
			}
			if err := tx.Create(&newRow).Error; err != nil {
				return fmt.Errorf("create cloned sink %q: %w", newRow.Name, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m.ListByEnvironment(targetEnvID)
}

// Seed translates the resolved service configuration (logger section
// and primary DB connection) into LogSink rows using create-if-missing
// semantics. The configuration may have been provided via flags,
// environment variables, or a YAML file — by the time it reaches here
// viper has merged them into a single *config.ServiceParameters, so the
// seed source is "the service configuration", not any one of those
// inputs in isolation.
//
// On first boot it writes one row per non-empty entry in logger.types
// (or the legacy logger.type). Existing rows are never overwritten —
// operator DB edits win.
//
// logger.alwaysLog is honored: if true and no db sink is among the
// configured types, a synthetic db sink named __always_log_db__ is
// seeded using the primary DB connection (params.DB).
func (m *LogSinksManager) Seed(params *config.ServiceParameters, envID uint) error {
	cfg := params.Logger
	primaryDB := params.DB
	if cfg == nil {
		// No logger section in the service configuration — seed a single
		// db sink pointing at the primary DB so logs are not silently
		// dropped on first boot in deployments that relied on the
		// historical default.
		if primaryDB == nil {
			return nil
		}
		return m.seedDefaultDB(primaryDB, envID)
	}

	types := config.LoggerTypes(cfg)
	seenDB := false
	for i, typ := range types {
		typ = normalizeType(typ)
		if typ == config.LoggingDB {
			seenDB = true
		}
		row, err := m.configRowForType(cfg, primaryDB, typ, i, envID)
		if err != nil {
			return err
		}
		if row == nil {
			continue
		}
		if err := m.seedRow(row); err != nil {
			return err
		}
	}

	if cfg.AlwaysLog && !seenDB && primaryDB != nil {
		// Synthetic always-log DB sink so the historical alwaysLog=true
		// behavior is preserved in the DB-backed model.
		cfgJSON, err := json.Marshal(primaryDB)
		if err != nil {
			return fmt.Errorf("marshal alwaysLog db config: %w", err)
		}
		row := LogSink{
			Name:          "__always_log_db__",
			EnvironmentID: envID,
			Type:          config.LoggingDB,
			Enabled:       true,
			Order:         999,
			Config:        string(cfgJSON),
			Source:        SourceService,
			Info:          "Auto-seeded from logger.alwaysLog",
		}
		if err := m.seedRow(&row); err != nil {
			return err
		}
	}
	return nil
}

// seedDefaultDB seeds a single db sink pointing at the primary DB when
// the service configuration has no logger section at all.
func (m *LogSinksManager) seedDefaultDB(primaryDB *config.YAMLConfigurationDB, envID uint) error {
	cfgJSON, err := json.Marshal(primaryDB)
	if err != nil {
		return fmt.Errorf("marshal default db config: %w", err)
	}
	row := LogSink{
		Name:          "default-db",
		EnvironmentID: envID,
		Type:          config.LoggingDB,
		Enabled:       true,
		Order:         0,
		Config:        string(cfgJSON),
		Source:        SourceService,
		Info:          "Auto-seeded from primary DB config (no logger section)",
	}
	return m.seedRow(&row)
}

// configRowForType builds a seed LogSink for one configured type. It
// reads the matching sub-block from the resolved logger section and
// marshals it to JSON. Returns nil, nil for types whose block is
// absent and have no sane default.
func (m *LogSinksManager) configRowForType(cfg *config.YAMLConfigurationLogger, primaryDB *config.YAMLConfigurationDB, typ string, order int, envID uint) (*LogSink, error) {
	name := "seeded-" + typ
	switch typ {
	case config.LoggingNone, config.LoggingStdout:
		return &LogSink{
			Name: name, EnvironmentID: envID, Type: typ,
			Enabled: true, Order: order, Config: "{}",
			Source: SourceService, Info: "Seeded from service configuration",
		}, nil
	case config.LoggingFile:
		if cfg.Local == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Local)
	case config.LoggingDB:
		// When LoggerDBSame is true the operator explicitly asked to
		// reuse the primary DB connection — use params.DB (primaryDB)
		// which carries the real connection details. Also fall back to
		// primaryDB when the logger-specific db block is absent or
		// all-zero, so the seeded row is never an empty shell.
		dbCfg := cfg.DB
		if cfg.LoggerDBSame || sameDBPtr(cfg.DB, primaryDB) || isEmptyDBConfig(cfg.DB) {
			dbCfg = primaryDB
		}
		if dbCfg == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, dbCfg)
	case config.LoggingSplunk:
		if cfg.Splunk == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Splunk)
	case config.LoggingGraylog:
		if cfg.Graylog == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Graylog)
	case config.LoggingLogstash:
		if cfg.Logstash == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Logstash)
	case config.LoggingKinesis:
		if cfg.Kinesis == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Kinesis)
	case config.LoggingS3:
		if cfg.S3 == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.S3)
	case config.LoggingKafka:
		if cfg.Kafka == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Kafka)
	case config.LoggingElastic:
		if cfg.Elastic == nil {
			return nil, nil
		}
		return m.marshalConfigRow(name, typ, order, envID, cfg.Elastic)
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidSinkType, typ)
	}
}

func (m *LogSinksManager) marshalConfigRow(name, typ string, order int, envID uint, cfg any) (*LogSink, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s config: %w", typ, err)
	}
	return &LogSink{
		Name: name, EnvironmentID: envID, Type: typ,
		Enabled: true, Order: order, Config: string(raw),
		Source: SourceService, Info: "Seeded from service configuration",
	}, nil
}

// seedRow creates a row only if no row with the same (Name,
// EnvironmentID) exists. If the row already exists and was not edited
// through the API (Source != "db"), the config is synced to the current
// service-config value — so a row that was seeded empty on a previous
// boot (e.g. due to a LoggerDBSame bug) gets populated on the next boot
// without clobbering operator edits.
func (m *LogSinksManager) seedRow(row *LogSink) error {
	if err := m.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error; err != nil {
		return fmt.Errorf("seed row %q: %w", row.Name, err)
	}
	// Sync config for existing non-DB-edited seed rows. This is the
	// same pattern as serviceconfig.Seed's metadata sync, but applied
	// to the config blob: schema-controlled data must always reflect
	// the current service configuration, not a stale empty seed from
	// a previous boot. Operator-edited rows (Source="db") are never
	// touched.
	if err := m.DB.Model(&LogSink{}).
		Where("name = ? AND environment_id = ? AND (source = ? OR source = ?)",
			row.Name, row.EnvironmentID, SourceService, SourceYAML).
		Updates(map[string]any{
			"config": row.Config,
			"type":   row.Type,
			"info":   row.Info,
		}).Error; err != nil {
		return fmt.Errorf("sync seed row %q: %w", row.Name, err)
	}
	return nil
}

// sameDBPtr reports whether two YAMLConfigurationDB pointers point to
// equivalent configs. Mirrors logging.sameConfigDBPtr so the YAML
// "loggerDBSame" detection stays consistent.
func sameDBPtr(a, b *config.YAMLConfigurationDB) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Type == b.Type && a.Host == b.Host && a.Port == b.Port && a.Name == b.Name
}

// isEmptyDBConfig reports whether a YAMLConfigurationDB has no
// meaningful connection details set — the zero value that init()
// populates when the operator did not fill in the logger.db block.
// Used to fall back to the primary DB so the seeded row is never an
// empty shell.
func isEmptyDBConfig(db *config.YAMLConfigurationDB) bool {
	if db == nil {
		return true
	}
	return db.Type == "" && db.Host == "" && db.Port == 0 && db.Name == "" && db.FilePath == ""
}

// RedactedConfig returns the Config JSON with secret fields replaced by
// the placeholder "***", for the sink Type. Non-secret types return the
// raw Config unchanged. If the Config does not decode as a JSON object,
// the raw value is returned untouched (best-effort redaction).
func RedactedConfig(typ, cfgJSON string) string {
	spec, ok := Registry[typ]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return cfgJSON
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &obj); err != nil {
		return cfgJSON
	}
	for _, key := range spec.SecretFields {
		if _, present := obj[key]; present {
			obj[key] = "***"
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return cfgJSON
	}
	return string(out)
}

// MergeSecrets replaces any "***" placeholder values in newCfgJSON with
// the corresponding values from prevCfgJSON. Used by the API Update
// handler so an edit that did not touch a secret field preserves the
// previously stored secret instead of writing the placeholder.
func MergeSecrets(typ, prevCfgJSON, newCfgJSON string) (string, error) {
	spec, ok := Registry[typ]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return newCfgJSON, nil
	}
	var prev, next map[string]any
	if err := json.Unmarshal([]byte(prevCfgJSON), &prev); err != nil {
		return "", fmt.Errorf("decode prev config: %w", err)
	}
	if err := json.Unmarshal([]byte(newCfgJSON), &next); err != nil {
		return "", fmt.Errorf("decode new config: %w", err)
	}
	for _, key := range spec.SecretFields {
		v, ok := next[key]
		if !ok {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		if s == "***" || s == "" {
			if pv, pok := prev[key]; pok {
				next[key] = pv
			}
		}
	}
	out, err := json.Marshal(next)
	if err != nil {
		return "", fmt.Errorf("encode merged config: %w", err)
	}
	return string(out), nil
}

// BuildExporters constructs a logging.MultiExporter from a set of sink
// rows for one environment. Disabled sinks are skipped. Sink build
// errors are logged and the sink is skipped (one bad sink does not
// break the whole fan-out). Returns a MultiExporter containing all
// enabled, buildable sinks.
func BuildExporters(rows []LogSink, smgr *settings.Settings) *logging.MultiExporter {
	exporters := make([]logging.DataExporter, 0, len(rows))
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		spec, ok := Registry[row.Type]
		if !ok {
			log.Error().Str("sink", row.Name).Str("type", row.Type).Msg("unknown sink type, skipping")
			continue
		}
		decoded, err := spec.Decode(json.RawMessage(row.Config))
		if err != nil {
			log.Error().Err(err).Str("sink", row.Name).Msg("decode sink config, skipping")
			continue
		}
		exp, err := spec.Build(decoded, smgr)
		if err != nil {
			log.Error().Err(err).Str("sink", row.Name).Msg("build sink exporter, skipping")
			continue
		}
		exporters = append(exporters, exp)
	}
	return logging.NewMultiExporter(exporters...)
}

// BuildExportersForEnvironments builds a map of envID -> MultiExporter
// for every environment that has sinks, plus the global (key 0) set.
// Used at TLS boot and on reload. Errors for individual sinks are
// logged inside BuildExporters; this function never returns an error
// for a buildable-but-broken sink — it only returns an error if the DB
// query itself fails.
func (m *LogSinksManager) BuildExportersForEnvironments(smgr *settings.Settings) (map[uint]*logging.MultiExporter, error) {
	grouped, err := m.AllGrouped()
	if err != nil {
		return nil, err
	}
	out := make(map[uint]*logging.MultiExporter, len(grouped))
	for envID, rows := range grouped {
		out[envID] = BuildExporters(rows, smgr)
	}
	return out, nil
}
