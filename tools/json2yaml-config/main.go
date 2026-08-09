// json2yaml-config converts the old (pre 0.5.0) osctrl JSON configuration
// files into the single YAML configuration file used by osctrl-tls and
// osctrl-api since the YAML migration.
//
// The old configuration was split in multiple JSON files, each one wrapped
// in a top-level key:
//
//	tls.json / api.json                -> {"tls": {...}} service values
//	db.json                           -> {"db": {...}} PostgreSQL backend
//	redis.json                        -> {"redis": {...}} cache
//	jwt.json                          -> {"jwt": {...}} JWT for api
//	saml.json                         -> {"saml": {...}} SAML
//	logger_<service>.json             -> {"graylog": {...}} et al, keyed by logger type
//	carver_<service>.json             -> {"s3": {...}} S3 carver
//
// Usage:
//
//	go run ./tools/json2yaml-config -service tls -config config/tls.json \
//	  -db config/db.json -redis config/redis.json -output tls.yml
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.yaml.in/yaml/v2"
)

// flexInt accepts both JSON strings ("9000") and numbers (9000), since the
// old configuration files used strings for ports.
type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*f = 0
			return nil
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid numeric value %q", s)
		}
		*f = flexInt(v)
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

// flexDuration accepts both JSON strings ("5s") and numbers (nanoseconds),
// since time.Duration values could be serialized either way.
type flexDuration string

func (f *flexDuration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "" {
			if _, err := time.ParseDuration(s); err != nil {
				return fmt.Errorf("invalid duration %q", s)
			}
		}
		*f = flexDuration(s)
		return nil
	}
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*f = flexDuration(time.Duration(n).String())
	return nil
}

// ////////////////////////////////////////////////////////////////// old JSON structures

type oldService struct {
	Listener        string  `json:"listener"`
	Port            flexInt `json:"port"`
	LogLevel        string  `json:"logLevel"`
	LogFormat       string  `json:"logFormat"`
	MetricsListener string  `json:"metricsListener"`
	MetricsPort     flexInt `json:"metricsPort"`
	MetricsEnabled  bool    `json:"metricsEnabled"`
	Host            string  `json:"host"`
	Auth            string  `json:"auth"`
	Logger          string  `json:"logger"`
	Carver          string  `json:"carver"`
}

type oldDB struct {
	Type            string  `json:"type"`
	Host            string  `json:"host"`
	Port            flexInt `json:"port"`
	Name            string  `json:"name"`
	Username        string  `json:"username"`
	Password        string  `json:"password"`
	SSLMode         string  `json:"sslmode"`
	MaxIdleConns    int     `json:"maxIdleConns"`
	MaxOpenConns    int     `json:"maxOpenConns"`
	ConnMaxLifetime int     `json:"connMaxLifetime"`
	ConnRetry       int     `json:"connRetry"`
}

type oldRedis struct {
	Host             string  `json:"host"`
	Port             flexInt `json:"port"`
	Password         string  `json:"password"`
	ConnectionString string  `json:"connectionstring"`
	DB               int     `json:"db"`
	ConnRetry        int     `json:"connRetry"`
}

type oldJWT struct {
	JWTSecret     string `json:"jwtSecret"`
	HoursToExpire int    `json:"hoursToExpire"`
}

type oldSAML struct {
	CertPath     string `json:"certpath"`
	KeyPath      string `json:"keypath"`
	MetaDataURL  string `json:"metadataurl"`
	RootURL      string `json:"rooturl"`
	LoginURL     string `json:"loginurl"`
	LogoutURL    string `json:"logouturl"`
	JITProvision bool   `json:"jitprovision"`
}

type oldGraylog struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Queries string `json:"queries"`
	Status  string `json:"status"`
	Results string `json:"results"`
}

type oldSplunk struct {
	URL   string `json:"url"`
	Token string `json:"token"`
	Host  string `json:"host"`
	Index string `json:"index"`
}

type oldElastic struct {
	Host           string `json:"host"`
	Port           string `json:"port"`
	IndexPrefix    string `json:"indexPrefix"`
	DateSeparator  string `json:"dateSeparator"`
	IndexSeparator string `json:"indexSeparator"`
}

type oldLogstash struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}

type oldKinesis struct {
	Stream          string `json:"stream"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key"`
	SecretAccessKey string `json:"secret_key"`
	SessionToken    string `json:"session_token"`
}

// Note: "secretAccesKey" (single s) is the original typo in the old JSON tag
type oldS3 struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKey       string `json:"accessKey"`
	SecretAccessKey string `json:"secretAccesKey"`
}

type oldKafkaSASL struct {
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type oldKafka struct {
	BootstrapServers  string       `json:"bootstrap_servers"`
	SSLCALocation     string       `json:"ssl_ca_location"`
	ConnectionTimeout flexDuration `json:"connection_timeout"`
	SASL              oldKafkaSASL `json:"sasl"`
	Topic             string       `json:"topic"`
}

// ////////////////////////////////////////////////////////////////// new YAML structures

type yamlService struct {
	Listener  string `yaml:"listener"`
	Port      int    `yaml:"port"`
	LogLevel  string `yaml:"logLevel"`
	LogFormat string `yaml:"logFormat"`
	Host      string `yaml:"host"`
	Auth      string `yaml:"auth"`
	AuditLog  bool   `yaml:"auditLog"`
}

type yamlDB struct {
	Type            string `yaml:"type"`
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	Name            string `yaml:"name"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	SSLMode         string `yaml:"sslmode"`
	MaxIdleConns    int    `yaml:"maxIdleConns"`
	MaxOpenConns    int    `yaml:"maxOpenConns"`
	ConnMaxLifetime int    `yaml:"connMaxLifetime"`
	ConnRetry       int    `yaml:"connRetry"`
	FilePath        string `yaml:"filePath"`
}

type yamlWriter struct {
	WriterBatchSize  int    `yaml:"writerBatchSize"`
	WriterTimeout    string `yaml:"writerTimeout"`
	WriterBufferSize int    `yaml:"writerBufferSize"`
}

type yamlRedis struct {
	Host             string `yaml:"host"`
	Port             int    `yaml:"port"`
	Password         string `yaml:"password"`
	ConnectionString string `yaml:"connectionString"`
	DB               int    `yaml:"db"`
	ConnRetry        int    `yaml:"connRetry"`
}

type yamlOsquery struct {
	Version     string `yaml:"version"`
	TablesFile  string `yaml:"tablesFile"`
	Logger      bool   `yaml:"logger"`
	Config      bool   `yaml:"config"`
	Query       bool   `yaml:"query"`
	Carve       bool   `yaml:"carve"`
	Accelerated *bool  `yaml:"accelerated,omitempty"`
}

type yamlOsctrld struct {
	Enabled bool `yaml:"enabled"`
}

type yamlMetrics struct {
	Enabled  bool   `yaml:"enabled"`
	Listener string `yaml:"listener"`
	Port     int    `yaml:"port"`
}

type yamlSAML struct {
	CertPath     string `yaml:"certPath"`
	KeyPath      string `yaml:"keyPath"`
	MetadataURL  string `yaml:"metadataUrl"`
	RootURL      string `yaml:"rootUrl"`
	LoginURL     string `yaml:"loginUrl"`
	LogoutURL    string `yaml:"logoutUrl"`
	JITProvision bool   `yaml:"jitProvision"`
	SPInitiated  bool   `yaml:"spInitiated"`
}

type yamlOIDC struct {
	IssuerURL      string   `yaml:"issuerUrl"`
	ClientID       string   `yaml:"clientId"`
	ClientSecret   string   `yaml:"clientSecret"`
	RedirectURL    string   `yaml:"redirectUrl"`
	Scopes         []string `yaml:"scopes"`
	UsernameClaim  string   `yaml:"usernameClaim"`
	GroupsClaim    string   `yaml:"groupsClaim"`
	RequiredGroups []string `yaml:"requiredGroups"`
	JITProvision   bool     `yaml:"jitProvision"`
}

type yamlJWT struct {
	JWTSecret     string `yaml:"jwtSecret"`
	HoursToExpire int    `yaml:"hoursToExpire"`
}

type yamlTLS struct {
	Termination     bool   `yaml:"termination"`
	CertificateFile string `yaml:"certificateFile"`
	KeyFile         string `yaml:"keyFile"`
}

type yamlS3 struct {
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	AccessKey       string `yaml:"accessKey"`
	SecretAccessKey string `yaml:"secretAccessKey"`
}

type yamlGraylog struct {
	URL     string `yaml:"url"`
	Host    string `yaml:"host"`
	Queries string `yaml:"queries"`
	Status  string `yaml:"status"`
	Results string `yaml:"results"`
}

type yamlElastic struct {
	Host           string `yaml:"host"`
	Port           string `yaml:"port"`
	IndexPrefix    string `yaml:"indexPrefix"`
	DateSeparator  string `yaml:"dateSeparator"`
	IndexSeparator string `yaml:"indexSeparator"`
}

type yamlSplunk struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
	Host  string `yaml:"host"`
	Index string `yaml:"index"`
}

type yamlLogstash struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Path     string `yaml:"path"`
}

type yamlKinesis struct {
	Stream       string `yaml:"stream"`
	Region       string `yaml:"region"`
	Endpoint     string `yaml:"endpoint"`
	AccessKey    string `yaml:"accessKey"`
	SecretKey    string `yaml:"secretKey"`
	SessionToken string `yaml:"sessionToken"`
}

type yamlKafkaSASL struct {
	Mechanism string `yaml:"mechanism"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
}

type yamlKafka struct {
	BootstrapServers  string        `yaml:"bootstrapServers"`
	SSLCALocation     string        `yaml:"sslCALocation"`
	ConnectionTimeout string        `yaml:"connectionTimeout"`
	SASL              yamlKafkaSASL `yaml:"sasl"`
	Topic             string        `yaml:"topic"`
}

type yamlLocalLogger struct {
	FilePath   string `yaml:"filePath"`
	MaxSize    int    `yaml:"maxSize"`
	MaxBackups int    `yaml:"maxBackups"`
	MaxAge     int    `yaml:"maxAge"`
	Compress   bool   `yaml:"compress"`
}

type yamlLogger struct {
	Type         string          `yaml:"type"`
	LoggerDBSame bool            `yaml:"loggerDBSame"`
	AlwaysLog    bool            `yaml:"alwaysLog"`
	DB           yamlDB          `yaml:"db"`
	S3           yamlS3          `yaml:"s3"`
	Graylog      yamlGraylog     `yaml:"graylog"`
	Elastic      yamlElastic     `yaml:"elastic"`
	Splunk       yamlSplunk      `yaml:"splunk"`
	Logstash     yamlLogstash    `yaml:"logstash"`
	Kinesis      yamlKinesis     `yaml:"kinesis"`
	Kafka        yamlKafka       `yaml:"kafka"`
	Local        yamlLocalLogger `yaml:"local"`
}

type yamlLocalCarver struct {
	CarvesDir string `yaml:"carvesDir"`
}

type yamlCarver struct {
	Type  string          `yaml:"type"`
	S3    yamlS3          `yaml:"s3"`
	Local yamlLocalCarver `yaml:"local"`
}

type yamlDebug struct {
	EnableHTTP bool   `yaml:"enableHttp"`
	HTTPFile   string `yaml:"httpFile"`
	ShowBody   bool   `yaml:"showBody"`
}

type yamlConfig struct {
	Service     yamlService  `yaml:"service"`
	DB          yamlDB       `yaml:"db"`
	BatchWriter *yamlWriter  `yaml:"batchwriter,omitempty"`
	Redis       yamlRedis    `yaml:"redis"`
	Osquery     yamlOsquery  `yaml:"osquery"`
	Osctrld     *yamlOsctrld `yaml:"osctrld,omitempty"`
	Metrics     *yamlMetrics `yaml:"metrics,omitempty"`
	SAML        *yamlSAML    `yaml:"saml,omitempty"`
	OIDC        *yamlOIDC    `yaml:"oidc,omitempty"`
	JWT         *yamlJWT     `yaml:"jwt,omitempty"`
	TLS         yamlTLS      `yaml:"tls"`
	Logger      yamlLogger   `yaml:"logger"`
	Carver      yamlCarver   `yaml:"carver"`
	Debug       yamlDebug    `yaml:"debug"`
}

// ////////////////////////////////////////////////////////////////// helpers

// loadJSONSection reads a JSON file wrapped in a top-level key and decodes
// the value under wantKey into out. If wantKey is not present and the file
// has exactly one top-level key, that one is used instead.
func loadJSONSection(file, wantKey string, out interface{}) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return fmt.Errorf("parsing %s: %w", file, err)
	}
	raw, ok := wrapper[wantKey]
	if !ok {
		if len(wrapper) != 1 {
			return fmt.Errorf("key %q not found in %s (keys: %v)", wantKey, file, keysOf(wrapper))
		}
		for k, v := range wrapper {
			warnf("key %q not found in %s, using %q instead", wantKey, file, k)
			raw = v
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parsing %q section of %s: %w", wantKey, file, err)
	}
	return nil
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func defaultString(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func defaultInt(value, def int) int {
	if value == 0 {
		return def
	}
	return value
}

// ////////////////////////////////////////////////////////////////// conversion

const (
	defOsqueryVersion = "5.23.1"
	defOsqueryTables  = "./data/5.23.1.json"
)

func main() {
	var (
		service    = flag.String("service", "", "Service to convert the configuration for: tls or api")
		configFile = flag.String("config", "", "Path to the old service JSON file (tls.json or api.json)")
		dbFile     = flag.String("db", "", "Path to the old db.json file (optional)")
		redisFile  = flag.String("redis", "", "Path to the old redis.json file (optional)")
		jwtFile    = flag.String("jwt", "", "Path to the old jwt.json file (optional, api only)")
		samlFile   = flag.String("saml", "", "Path to the old saml.json file (optional)")
		loggerFile = flag.String("logger", "", "Path to the old logger JSON file, keyed by logger type (optional)")
		carverFile = flag.String("carver", "", "Path to the old S3 carver JSON file (optional)")
		outFile    = flag.String("output", "", "Path to write the YAML output to (default: <service>.yml, use - for stdout)")
	)
	flag.Parse()

	if *service != "tls" && *service != "api" {
		fatalf("-service must be one of: tls, api")
	}
	if *configFile == "" {
		fatalf("-config is required (path to the old %s.json)", *service)
	}

	var svc oldService
	if err := loadJSONSection(*configFile, *service, &svc); err != nil {
		fatalf("%v", err)
	}

	out := yamlConfig{
		Service: yamlService{
			Listener:  defaultString(svc.Listener, "0.0.0.0"),
			Port:      defaultInt(int(svc.Port), 9000),
			LogLevel:  defaultString(svc.LogLevel, "info"),
			LogFormat: defaultString(svc.LogFormat, "json"),
			Host:      defaultString(svc.Host, "0.0.0.0"),
			Auth:      defaultString(svc.Auth, "none"),
			AuditLog:  false,
		},
		DB: yamlDB{
			Type:            "postgres",
			Host:            "127.0.0.1",
			Port:            5432,
			Name:            "osctrl",
			Username:        "postgres",
			Password:        "postgres",
			SSLMode:         "disable",
			MaxIdleConns:    20,
			MaxOpenConns:    100,
			ConnMaxLifetime: 30,
			ConnRetry:       10,
			FilePath:        "./osctrl.db",
		},
		Redis: yamlRedis{
			Host:      "127.0.0.1",
			Port:      6379,
			DB:        0,
			ConnRetry: 10,
		},
		Osquery: yamlOsquery{
			Version:    defOsqueryVersion,
			TablesFile: defOsqueryTables,
			Logger:     true,
			Config:     true,
			Query:      true,
			Carve:      true,
		},
		TLS: yamlTLS{
			Termination:     false,
			CertificateFile: "./config/tls.crt",
			KeyFile:         "./config/tls.key",
		},
		Logger: yamlLogger{
			Type: defaultString(svc.Logger, "db"),
			Kafka: yamlKafka{
				ConnectionTimeout: "5s",
			},
		},
		Carver: yamlCarver{
			Type:  defaultString(svc.Carver, "db"),
			Local: yamlLocalCarver{CarvesDir: "./carved_files/"},
		},
		Debug: yamlDebug{
			EnableHTTP: false,
			HTTPFile:   fmt.Sprintf("./debug-http-%s.log", *service),
			ShowBody:   false,
		},
	}

	// Sections that only exist for some services
	switch *service {
	case "tls":
		accelerated := false
		out.Osquery.Accelerated = &accelerated
		out.BatchWriter = &yamlWriter{
			WriterBatchSize:  50,
			WriterTimeout:    "1m0s",
			WriterBufferSize: 2000,
		}
		out.Osctrld = &yamlOsctrld{Enabled: false}
		out.Metrics = &yamlMetrics{
			Enabled:  svc.MetricsEnabled,
			Listener: defaultString(svc.MetricsListener, "127.0.0.1"),
			Port:     defaultInt(int(svc.MetricsPort), 9090),
		}
	case "api":
		out.JWT = &yamlJWT{HoursToExpire: 3}
	}

	if *dbFile != "" {
		var db oldDB
		if err := loadJSONSection(*dbFile, "db", &db); err != nil {
			fatalf("%v", err)
		}
		out.DB.Type = defaultString(db.Type, "postgres")
		out.DB.Host = defaultString(db.Host, "127.0.0.1")
		out.DB.Port = defaultInt(int(db.Port), 5432)
		out.DB.Name = defaultString(db.Name, "osctrl")
		out.DB.Username = db.Username
		out.DB.Password = db.Password
		out.DB.SSLMode = defaultString(db.SSLMode, "disable")
		out.DB.MaxIdleConns = defaultInt(db.MaxIdleConns, 20)
		out.DB.MaxOpenConns = defaultInt(db.MaxOpenConns, 100)
		out.DB.ConnMaxLifetime = defaultInt(db.ConnMaxLifetime, 30)
		out.DB.ConnRetry = defaultInt(db.ConnRetry, 10)
	} else {
		warnf("no -db file provided, using default database values")
	}

	if *redisFile != "" {
		var rd oldRedis
		if err := loadJSONSection(*redisFile, "redis", &rd); err != nil {
			fatalf("%v", err)
		}
		out.Redis.Host = defaultString(rd.Host, "127.0.0.1")
		out.Redis.Port = defaultInt(int(rd.Port), 6379)
		out.Redis.Password = rd.Password
		out.Redis.ConnectionString = rd.ConnectionString
		out.Redis.DB = rd.DB
		out.Redis.ConnRetry = defaultInt(rd.ConnRetry, 10)
	} else {
		warnf("no -redis file provided, using default redis values")
	}

	if *jwtFile != "" {
		if out.JWT == nil {
			warnf("-jwt provided but the %s service has no JWT section, ignoring", *service)
		} else {
			var jw oldJWT
			if err := loadJSONSection(*jwtFile, "jwt", &jw); err != nil {
				fatalf("%v", err)
			}
			out.JWT.JWTSecret = jw.JWTSecret
			out.JWT.HoursToExpire = defaultInt(jw.HoursToExpire, 3)
		}
	}

	if *samlFile != "" {
		if out.SAML == nil {
			warnf("-saml provided but the %s service has no SAML section, ignoring", *service)
		} else {
			var sm oldSAML
			if err := loadJSONSection(*samlFile, "saml", &sm); err != nil {
				fatalf("%v", err)
			}
			out.SAML.CertPath = sm.CertPath
			out.SAML.KeyPath = sm.KeyPath
			out.SAML.MetadataURL = sm.MetaDataURL
			out.SAML.RootURL = sm.RootURL
			out.SAML.LoginURL = sm.LoginURL
			out.SAML.LogoutURL = sm.LogoutURL
			out.SAML.JITProvision = sm.JITProvision
		}
	}

	if *loggerFile != "" {
		if err := convertLogger(*loggerFile, &out.Logger); err != nil {
			fatalf("%v", err)
		}
	}

	if *carverFile != "" {
		var s3 oldS3
		if err := loadJSONSection(*carverFile, "s3", &s3); err != nil {
			fatalf("%v", err)
		}
		out.Carver.S3 = yamlS3(s3)
	}

	data, err := yaml.Marshal(out)
	if err != nil {
		fatalf("generating YAML: %v", err)
	}
	header := fmt.Sprintf("# YAML configuration for osctrl-%s\n# Converted from pre-0.5.0 JSON configuration by tools/json2yaml-config\n\n", *service)
	output := append([]byte(header), data...)

	target := *outFile
	if target == "" {
		target = *service + ".yml"
	}
	if target == "-" {
		fmt.Print(string(output))
		return
	}
	if err := os.WriteFile(target, output, 0600); err != nil {
		fatalf("writing %s: %v", target, err)
	}
	fmt.Printf("Converted configuration written to %s\n", target)
}

// convertLogger loads the old logger-specific JSON file (keyed by logger
// type) and fills the matching subsection of the new logger configuration.
func convertLogger(file string, logger *yamlLogger) error {
	switch logger.Type {
	case "graylog":
		var g oldGraylog
		if err := loadJSONSection(file, "graylog", &g); err != nil {
			return err
		}
		logger.Graylog = yamlGraylog(g)
	case "splunk":
		var s oldSplunk
		if err := loadJSONSection(file, "splunk", &s); err != nil {
			return err
		}
		logger.Splunk = yamlSplunk(s)
	case "elastic":
		var e oldElastic
		if err := loadJSONSection(file, "elastic", &e); err != nil {
			return err
		}
		logger.Elastic = yamlElastic(e)
	case "logstash":
		var l oldLogstash
		if err := loadJSONSection(file, "logstash", &l); err != nil {
			return err
		}
		logger.Logstash = yamlLogstash(l)
	case "kinesis":
		var k oldKinesis
		if err := loadJSONSection(file, "kinesis", &k); err != nil {
			return err
		}
		logger.Kinesis = yamlKinesis{
			Stream:       k.Stream,
			Region:       k.Region,
			Endpoint:     k.Endpoint,
			AccessKey:    k.AccessKeyID,
			SecretKey:    k.SecretAccessKey,
			SessionToken: k.SessionToken,
		}
	case "s3":
		var s3 oldS3
		if err := loadJSONSection(file, "s3", &s3); err != nil {
			return err
		}
		logger.S3 = yamlS3(s3)
	case "kafka":
		var k oldKafka
		if err := loadJSONSection(file, "kafka", &k); err != nil {
			return err
		}
		logger.Kafka = yamlKafka{
			BootstrapServers:  k.BootstrapServers,
			SSLCALocation:     k.SSLCALocation,
			ConnectionTimeout: defaultString(string(k.ConnectionTimeout), "5s"),
			SASL:              yamlKafkaSASL(k.SASL),
			Topic:             k.Topic,
		}
	case "none", "stdout", "file", "db":
		warnf("logger type %q does not use a separate configuration file, ignoring -logger", logger.Type)
	default:
		return fmt.Errorf("unknown logger type %q", logger.Type)
	}
	return nil
}
