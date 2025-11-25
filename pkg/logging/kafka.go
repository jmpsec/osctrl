package logging

import (
	"context"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"

	"github.com/rs/zerolog/log"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"github.com/twmb/tlscfg"
)

type LoggerKafka struct {
	config   config.KafkaConfiguration
	Enabled  bool
	producer *kgo.Client
}

func CreateLoggerKafka(config config.KafkaConfiguration) (*LoggerKafka, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(config.BootstrapServer),
		kgo.ConsumeTopics(config.Topic),
	}

	if config.ConnectionTimeout > 0 {
		kgo.DialTimeout(config.ConnectionTimeout)
	}

	// if we rely on SASL then populate the options
	if config.SASL.Mechanism != "" {
		if config.SASL.Username == "" {
			return nil, fmt.Errorf("SASL mechanism requires a username")
		}

		if config.SASL.Password == "" {
			return nil, fmt.Errorf("SASL mechanism requires a password")
		}
		auth := scram.Auth{
			User: config.SASL.Username,
			Pass: config.SASL.Password,
		}
		var mechanism sasl.Mechanism
		switch config.SASL.Mechanism {
		case "SCRAM-SHA-512":
			mechanism = auth.AsSha512Mechanism()
		case "SCRAM-SHA-256":
			mechanism = auth.AsSha256Mechanism()
		default:
			return nil, fmt.Errorf("unknown SASL mechanism '%s'", config.SASL.Mechanism)
		}

		opts = append(opts, kgo.SASL(mechanism))
	}

	if config.SSLCALocation != "" {
		caCert, err := os.ReadFile(config.SSLCALocation)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA Cert from '%s'", config.SSLCALocation)
		}
		cfg, err := tlscfg.New(tlscfg.WithCA(caCert, tlscfg.ForClient))
		if err != nil {
			return nil, fmt.Errorf("failed to use CA Cert for client side: %w", err)
		}
		opts = append(opts, kgo.DialTLSConfig(cfg))
	}

	producer, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka client: %w", err)
	}

	return &LoggerKafka{
		config:   config,
		Enabled:  true,
		producer: producer,
	}, nil
}

func (l *LoggerKafka) Settings(mgr *settings.Settings) {
	log.Warn().Msg("No kafka logging settings")
}

func (l *LoggerKafka) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Info().Msgf(
			"Sending %d bytes to Kafka topic %s for %s - %s",
			len(data), l.config.Topic, environment, uuid)
	}

	ctx := context.Background()
	key := []byte(uuid) // uuid is the unique id of the os-query agent host that sent this data
	rec := kgo.Record{Topic: l.config.Topic, Key: key, Value: data}
	l.producer.Produce(ctx, &rec, func(r *kgo.Record, err error) {
		if err != nil {
			log.Info().Msgf(
				"failed to produce message to kafka topic '%s'. details: %s",
				l.config.Topic, err)
		}
		if debug {
			log.Info().Msgf(
				"message with key '%s' was sent to topic '%s' successfully\n%s",
				key, l.config.Topic, string(data))
		}
	})
}
