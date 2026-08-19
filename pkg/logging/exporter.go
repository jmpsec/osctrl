package logging

import (
	"errors"
	"fmt"
	"strings"

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

// MultiExporter fans out one osquery payload to multiple destinations.
// A failing exporter is logged and returned, but does not prevent later
// exporters from receiving the same payload.
type MultiExporter struct {
	exporters []DataExporter
}

// NewMultiExporter creates a composite exporter from the provided destinations.
func NewMultiExporter(exporters ...DataExporter) *MultiExporter {
	return &MultiExporter{exporters: exporters}
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
