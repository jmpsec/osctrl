package logging

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

// ExportParams contains the metadata shared by every osquery data exporter.
// QueryName and Status are set only for on-demand query result exports.
type ExportParams struct {
	Environment string
	UUID        string
	QueryName   string
	Status      int
	Debug       bool
}

// DataExporter is a destination for osquery status, result, and query data.
type DataExporter interface {
	Name() string
	IsEnabled() bool
	Export(logType string, data []byte, params ExportParams) error
	// Close releases any resources held by this exporter (network
	// clients, DB connections, file handles). It is called by
	// LoggerTLS.ReplaceExporters on every exporter in the old set
	// during a hot reload so sinks are not leaked across reloads.
	// Stateless exporters return nil.
	Close() error
}

// SinkStats holds atomic per-sink counters — bytes sent and number of
// export calls. They are incremented on the hot path (every Export) via
// lock-free atomic adds and snapshotted by a background writer that
// flushes them to the database periodically. The sink ID links the
// counters back to the log_sinks row they belong to.
type SinkStats struct {
	SinkID      uint
	Exporter    DataExporter
	BytesSent   atomic.Int64
	ExportCount atomic.Int64
}

// CountedExporter wraps a DataExporter and increments SinkStats counters
// on every Export call. The wrapping is transparent — the underlying
// exporter receives the call as normal; the counters are incremented
// before the call so a failed export still counts the attempt.
type CountedExporter struct {
	inner DataExporter
	stats *SinkStats
}

// NewCountedExporter wraps exporter exp and records bytes/count in stats.
func NewCountedExporter(exp DataExporter, stats *SinkStats) *CountedExporter {
	stats.Exporter = exp
	return &CountedExporter{inner: exp, stats: stats}
}

func (c *CountedExporter) Name() string    { return c.inner.Name() }
func (c *CountedExporter) IsEnabled() bool { return c.inner.IsEnabled() }
func (c *CountedExporter) Close() error    { return c.inner.Close() }

func (c *CountedExporter) Export(logType string, data []byte, params ExportParams) error {
	c.stats.BytesSent.Add(int64(len(data)))
	c.stats.ExportCount.Add(1)
	return c.inner.Export(logType, data, params)
}

// Stats returns the SinkStats pointer, or nil if the exporter is not
// counted (e.g. a plain DataExporter that was not wrapped).
func (c *CountedExporter) Stats() *SinkStats { return c.stats }

// MultiExporter fans out one osquery payload to multiple destinations.
// A failing exporter is logged and returned, but does not prevent later
// exporters from receiving the same payload. It also holds per-exporter
// SinkStats counters so the background stats writer can snapshot them
// and persist bytes/count to the log_sinks table without touching the
// hot path.
type MultiExporter struct {
	exporters []DataExporter
	stats     []*SinkStats
}

// NewMultiExporter creates a composite exporter from the provided
// destinations. The stats slice is empty — callers that want
// per-exporter counters should use NewMultiExporterWithStats.
func NewMultiExporter(exporters ...DataExporter) *MultiExporter {
	return &MultiExporter{exporters: exporters}
}

// NewMultiExporterWithStats creates a composite exporter where each
// exporter is wrapped in a CountedExporter linked to its SinkStats.
// The returned stats slice can be snapshotted by a background writer.
func NewMultiExporterWithStats(entries []ExporterEntry) *MultiExporter {
	exporters := make([]DataExporter, 0, len(entries))
	stats := make([]*SinkStats, 0, len(entries))
	for _, e := range entries {
		s := &SinkStats{SinkID: e.SinkID}
		ce := NewCountedExporter(e.Exporter, s)
		exporters = append(exporters, ce)
		stats = append(stats, s)
	}
	return &MultiExporter{exporters: exporters, stats: stats}
}

// ExporterEntry pairs a sink DB row ID with its built DataExporter.
type ExporterEntry struct {
	SinkID   uint
	Exporter DataExporter
}

// Stats returns the per-exporter SinkStats slice, or nil if the
// MultiExporter was created without stats tracking.
func (m *MultiExporter) Stats() []*SinkStats {
	if m == nil {
		return nil
	}
	return m.stats
}

// Name returns a comma-separated list of destination names for diagnostics.
func (m *MultiExporter) Name() string {
	if m == nil {
		return ""
	}
	names := make([]string, 0, len(m.exporters))
	for _, exporter := range m.exporters {
		if exporter == nil {
			continue
		}
		names = append(names, exporter.Name())
	}
	return strings.Join(names, ",")
}

// ExporterNames returns the configured destination names in order.
func (m *MultiExporter) ExporterNames() []string {
	if m == nil {
		return nil
	}
	names := make([]string, 0, len(m.exporters))
	for _, exporter := range m.exporters {
		if exporter == nil {
			continue
		}
		names = append(names, exporter.Name())
	}
	return names
}

// IsEnabled returns true when at least one contained exporter is enabled.
func (m *MultiExporter) IsEnabled() bool {
	if m == nil {
		return false
	}
	for _, exporter := range m.exporters {
		if exporter != nil && exporter.IsEnabled() {
			return true
		}
	}
	return false
}

// Export sends data to every enabled destination.
func (m *MultiExporter) Export(logType string, data []byte, params ExportParams) error {
	if m == nil {
		return nil
	}
	var errs []error
	for _, exporter := range m.exporters {
		if exporter == nil || !exporter.IsEnabled() {
			continue
		}
		if err := exporter.Export(logType, data, params); err != nil {
			log.Err(err).Str("exporter", exporter.Name()).Str("type", logType).Msg("error exporting osquery data")
			errs = append(errs, fmt.Errorf("%s: %w", exporter.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Close closes every contained exporter. Errors are collected and
// joined; one exporter failing to close does not stop the rest from
// being closed.
func (m *MultiExporter) Close() error {
	if m == nil {
		return nil
	}
	var errs []error
	for _, exporter := range m.exporters {
		if exporter == nil {
			continue
		}
		if err := exporter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", exporter.Name(), err))
		}
	}
	return errors.Join(errs...)
}
