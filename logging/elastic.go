package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// ElasticConfiguration to hold all elastic configuration values
type ElasticConfiguration struct {
	Host           string `json:"host"`
	Port           string `json:"port"`
	IndexPrefix    string `json:"indexPrefix"`
	DateSeparator  string `json:"dateSeparator"`  // Expected is . for YYYY.MM.DD
	IndexSeparator string `json:"indexSeparator"` // Expected is - for prefix-YYYY.MM.DD
}

// LoggerElastic will be used to log data using Elastic
type LoggerElastic struct {
	Configuration ElasticConfiguration
	Enabled       bool
	Client        *elasticsearch.Client
}

// CreateLoggerElastic to initialize the logger
func CreateLoggerElastic(elasticFile string) (*LoggerElastic, error) {
	config, err := LoadElastic(elasticFile)
	if err != nil {
		return nil, err
	}
	cfg := elasticsearch.Config{
		Addresses: []string{
			fmt.Sprintf("http://%s:%s", config.Host, config.Port),
		},
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, err
	} else {
		log.Info().Msg("Elasticsearch client created")
		infoRes, err := es.Info()
		if err != nil {
			log.Err(err).Msg("Error getting Elasticsearch info")
		} else {
			defer infoRes.Body.Close()
			log.Info().Msgf("Elasticsearch info: %s", infoRes)
		}
	}
	l := &LoggerElastic{
		Configuration: config,
		Enabled:       true,
		Client:        es,
	}
	return l, nil
}

// LoadElastic - Function to load the Elastic configuration from JSON file
func LoadElastic(file string) (ElasticConfiguration, error) {
	var _elasticCfg ElasticConfiguration
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return _elasticCfg, err
	}
	cfgRaw := viper.Sub(settings.LoggingElastic)
	if cfgRaw == nil {
		return _elasticCfg, fmt.Errorf("JSON key %s not found in %s", settings.LoggingElastic, file)
	}
	if err := cfgRaw.Unmarshal(&_elasticCfg); err != nil {
		return _elasticCfg, err
	}
	// No errors!
	return _elasticCfg, nil
}

// IndexName - Function to return the index name
func (logE *LoggerElastic) IndexName() string {
	now := time.Now().UTC()
	fNow := strings.ReplaceAll(now.Format("2006-01-02"), "-", logE.Configuration.DateSeparator)
	return fmt.Sprintf("%s%s%s", logE.Configuration.IndexPrefix, logE.Configuration.IndexSeparator, fNow)
}

// Settings - Function to prepare settings for the logger
func (logE *LoggerElastic) Settings(mgr *settings.Settings) {
	log.Info().Msg("Setting Elastic logging settings")
}

// Send - Function that sends JSON logs to Elastic
func (logE *LoggerElastic) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("DebugService: Send %s to Elastic", logType)
	}
	if debug {
		log.Debug().Msgf("DebugService: Sending %d bytes to Elastic for %s - %s", len(data), environment, uuid)
	}
	var logs []interface{}
	if logType == types.QueryLog {
		// For on-demand queries, just a JSON blob with results and statuses
		var result interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			log.Err(err).Msgf("error parsing data %s", string(data))
		}
		logs = append(logs, result)
	} else {
		// For scheduled queries, convert the array in an array of multiple events
		if err := json.Unmarshal(data, &logs); err != nil {
			log.Err(err).Msgf("error parsing log %s", string(data))
		}
	}
	for _, l := range logs {
		jsonEvent, err := json.Marshal(l)
		if err != nil {
			log.Err(err).Msg("Error parsing data")
			continue
		}
		req := esapi.IndexRequest{
			Index:   logE.IndexName(),
			Body:    strings.NewReader(string(jsonEvent)),
			Refresh: "true",
		}
		res, err := req.Do(context.Background(), logE.Client)
		if err != nil {
			log.Err(err).Msg("Error indexing document")
		}
		defer res.Body.Close()
		if res.IsError() {
			log.Error().Msgf("Error response from Elasticsearch: %s", res.String())
		}
	}
	if debug {
		log.Debug().Msgf("DebugService: Sent %d bytes of %s to Elastic from %s:%s", len(data), logType, uuid, environment)
	}
}
