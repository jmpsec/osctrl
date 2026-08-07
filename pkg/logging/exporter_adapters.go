package logging

import (
	"strings"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
)

func (logDB *LoggerDB) Name() string {
	return config.LoggingDB
}

func (logDB *LoggerDB) IsEnabled() bool {
	return logDB != nil && logDB.Enabled
}

func (logDB *LoggerDB) Export(logType string, data []byte, params ExportParams) error {
	if logType == types.QueryLog {
		logDB.Query(data, params.Environment, params.UUID, params.QueryName, params.Status, params.Debug)
		return nil
	}
	logDB.Log(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logStdout *LoggerStdout) Name() string {
	return config.LoggingStdout
}

func (logStdout *LoggerStdout) IsEnabled() bool {
	return logStdout != nil && logStdout.Enabled
}

func (logStdout *LoggerStdout) Export(logType string, data []byte, params ExportParams) error {
	if logType == types.QueryLog {
		logStdout.Query(data, params.Environment, params.UUID, params.QueryName, params.Status, params.Debug)
		return nil
	}
	logStdout.Log(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logFile *LoggerFile) Name() string {
	return config.LoggingFile
}

func (logFile *LoggerFile) IsEnabled() bool {
	return logFile != nil && logFile.Enabled
}

func (logFile *LoggerFile) Export(logType string, data []byte, params ExportParams) error {
	if logType == types.QueryLog {
		logFile.Query(data, params.Environment, params.UUID, params.QueryName, params.Status, params.Debug)
		return nil
	}
	logFile.Log(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logNone *LoggerNone) Name() string {
	return config.LoggingNone
}

func (logNone *LoggerNone) IsEnabled() bool {
	return logNone != nil && logNone.Enabled
}

func (logNone *LoggerNone) Export(logType string, data []byte, params ExportParams) error {
	if logType == types.QueryLog {
		logNone.Query(data, params.Environment, params.UUID, params.QueryName, params.Status, params.Debug)
		return nil
	}
	logNone.Log(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logSP *LoggerSplunk) Name() string {
	return config.LoggingSplunk
}

func (logSP *LoggerSplunk) IsEnabled() bool {
	return logSP != nil && logSP.Enabled
}

func (logSP *LoggerSplunk) Export(logType string, data []byte, params ExportParams) error {
	logSP.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logGL *LoggerGraylog) Name() string {
	return config.LoggingGraylog
}

func (logGL *LoggerGraylog) IsEnabled() bool {
	return logGL != nil && logGL.Enabled
}

func (logGL *LoggerGraylog) Export(logType string, data []byte, params ExportParams) error {
	logGL.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logLS *LoggerLogstash) Name() string {
	return config.LoggingLogstash
}

func (logLS *LoggerLogstash) IsEnabled() bool {
	return logLS != nil && logLS.Enabled
}

func (logLS *LoggerLogstash) Export(logType string, data []byte, params ExportParams) error {
	logLS.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

// Send routes Logstash exports to the configured protocol.
func (logLS *LoggerLogstash) Send(logType string, data []byte, environment, uuid string, debug bool) {
	switch strings.ToLower(logLS.Configuration.Protocol) {
	case LogstashTCP:
		logLS.SendTCP(logType, data, environment, uuid, debug)
	case LogstashUDP:
		logLS.SendUDP(logType, data, environment, uuid, debug)
	default:
		logLS.SendHTTP(logType, data, environment, uuid, debug)
	}
}

func (logSK *LoggerKinesis) Name() string {
	return config.LoggingKinesis
}

func (logSK *LoggerKinesis) IsEnabled() bool {
	return logSK != nil && logSK.Enabled
}

func (logSK *LoggerKinesis) Export(logType string, data []byte, params ExportParams) error {
	logSK.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logS3 *LoggerS3) Name() string {
	return config.LoggingS3
}

func (logS3 *LoggerS3) IsEnabled() bool {
	return logS3 != nil && logS3.Enabled
}

func (logS3 *LoggerS3) Export(logType string, data []byte, params ExportParams) error {
	logS3.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (l *LoggerKafka) Name() string {
	return config.LoggingKafka
}

func (l *LoggerKafka) IsEnabled() bool {
	return l != nil && l.Enabled
}

func (l *LoggerKafka) Export(logType string, data []byte, params ExportParams) error {
	l.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}

func (logE *LoggerElastic) Name() string {
	return config.LoggingElastic
}

func (logE *LoggerElastic) IsEnabled() bool {
	return logE != nil && logE.Enabled
}

func (logE *LoggerElastic) Export(logType string, data []byte, params ExportParams) error {
	logE.Send(logType, data, params.Environment, params.UUID, params.Debug)
	return nil
}
