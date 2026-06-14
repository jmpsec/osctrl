package tui

import (
	"fmt"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/jmpsec/osctrl/tools/fake_news_go/internal/metrics"
)

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

type ViewModel struct {
	Mode       string
	Verdict    metrics.Verdict
	Dashboard  metrics.DashboardSnapshot
	Thresholds metrics.Thresholds
	ReportPath string
	Elapsed    time.Duration
}

type DashboardModel struct {
	Header              string
	Sweep               string
	Summary             string
	Footer              string
	HealthLabel         string
	HealthSeverity      Severity
	ErrorGaugeLabel     string
	ErrorGaugePercent   int
	LatencyGaugeLabel   string
	LatencyGaugePercent int
	OperationRows       [][]string
	EndpointRows        [][]string
	OperationSeverity   map[int]Severity
	EndpointSeverity    map[int]Severity
}

func NewDashboardModel(view ViewModel) DashboardModel {
	totals := view.Dashboard.Totals
	errorPercent := int(totals.ErrorRate * 100)
	latencyPercent := 0
	if view.Thresholds.MaxP95 > 0 {
		latencyPercent = int((float64(totals.P95) / float64(view.Thresholds.MaxP95)) * 100)
	}
	if latencyPercent > 100 {
		latencyPercent = 100
	}
	healthSeverity := severityFromState(view.Verdict, totals.ErrorRate, totals.P95, view.Thresholds)

	model := DashboardModel{
		Header: fmt.Sprintf(
			"MODE %s | VERDICT %s | ELAPSED %s",
			strings.ToUpper(view.Mode),
			strings.ToUpper(string(view.Verdict)),
			view.Elapsed.Round(time.Second),
		),
		Sweep: fmt.Sprintf(
			"STAGE %d | STABLE %d | TARGET %d | SETTLE %s | SAMPLE %s | LIMIT err<=%.2f p95<=%s",
			view.Dashboard.Sweep.Stage,
			view.Dashboard.Sweep.HighestStableStage,
			view.Dashboard.Sweep.TargetNodes,
			view.Dashboard.Sweep.SettleRemaining.Round(time.Second),
			view.Dashboard.Sweep.SampleRemaining.Round(time.Second),
			view.Thresholds.MaxErrorRate,
			view.Thresholds.MaxP95,
		),
		Summary: fmt.Sprintf(
			"REQ %d | OK %d | FAIL %d | MIN %s | AVG %s | P95 %s | P99 %s",
			totals.Count,
			totals.SuccessCount,
			totals.FailCount,
			totals.Min.Round(time.Millisecond),
			totals.Avg.Round(time.Millisecond),
			totals.P95.Round(time.Millisecond),
			totals.P99.Round(time.Millisecond),
		),
		Footer:              fmt.Sprintf("Q/Ctrl+C quit | report %s", view.ReportPath),
		HealthLabel:         fmt.Sprintf("HEALTH %s", strings.ToUpper(string(healthSeverity))),
		HealthSeverity:      healthSeverity,
		ErrorGaugeLabel:     fmt.Sprintf("ERR %.2f%%", totals.ErrorRate*100),
		ErrorGaugePercent:   clampPercent(errorPercent),
		LatencyGaugeLabel:   fmt.Sprintf("P95 %s", totals.P95.Round(time.Millisecond)),
		LatencyGaugePercent: clampPercent(latencyPercent),
		OperationRows: [][]string{
			{"Operation", "Count", "Error %", "P95", "P99"},
		},
		EndpointRows: [][]string{
			{"Endpoint", "Count", "Error %", "P95", "P99"},
		},
		OperationSeverity: map[int]Severity{},
		EndpointSeverity:  map[int]Severity{},
	}

	for _, op := range view.Dashboard.Operations {
		rowIdx := len(model.OperationRows)
		model.OperationRows = append(model.OperationRows, []string{
			op.Name,
			fmt.Sprintf("%d", op.Count),
			fmt.Sprintf("%.2f", op.ErrorRate*100),
			op.P95.Round(time.Millisecond).String(),
			op.P99.Round(time.Millisecond).String(),
		})
		model.OperationSeverity[rowIdx] = severityFromState(metrics.VerdictStable, op.ErrorRate, op.P95, view.Thresholds)
	}
	for _, endpoint := range view.Dashboard.Endpoints {
		rowIdx := len(model.EndpointRows)
		model.EndpointRows = append(model.EndpointRows, []string{
			endpoint.Name,
			fmt.Sprintf("%d", endpoint.Count),
			fmt.Sprintf("%.2f", endpoint.ErrorRate*100),
			endpoint.P95.Round(time.Millisecond).String(),
			endpoint.P99.Round(time.Millisecond).String(),
		})
		model.EndpointSeverity[rowIdx] = severityFromState(metrics.VerdictStable, endpoint.ErrorRate, endpoint.P95, view.Thresholds)
	}

	return model
}

func Render(view ViewModel) *ui.Grid {
	model := NewDashboardModel(view)

	header := widgets.NewParagraph()
	header.Title = "fake_news_go"
	header.Text = model.Header
	header.BorderStyle = ui.NewStyle(colorForSeverity(model.HealthSeverity))
	header.TextStyle = ui.NewStyle(ui.ColorWhite, ui.ColorClear, ui.ModifierBold)

	health := widgets.NewParagraph()
	health.Title = "Health"
	health.Text = model.HealthLabel + "\n" + model.Summary
	health.BorderStyle = ui.NewStyle(colorForSeverity(model.HealthSeverity))
	health.TextStyle = ui.NewStyle(colorForSeverity(model.HealthSeverity), ui.ColorClear, ui.ModifierBold)

	sweep := widgets.NewParagraph()
	sweep.Title = "Sweep"
	sweep.Text = model.Sweep
	sweep.BorderStyle = ui.NewStyle(ui.ColorCyan)
	sweep.TextStyle = ui.NewStyle(ui.ColorWhite)

	errorGauge := widgets.NewGauge()
	errorGauge.Title = model.ErrorGaugeLabel
	errorGauge.Percent = model.ErrorGaugePercent
	errorGauge.BarColor = colorForSeverity(severityForPercent(model.ErrorGaugePercent))
	errorGauge.BorderStyle = ui.NewStyle(errorGauge.BarColor)
	errorGauge.LabelStyle = ui.NewStyle(ui.ColorBlack, errorGauge.BarColor, ui.ModifierBold)

	latencyGauge := widgets.NewGauge()
	latencyGauge.Title = model.LatencyGaugeLabel
	latencyGauge.Percent = model.LatencyGaugePercent
	latencyGauge.BarColor = colorForSeverity(severityForPercent(model.LatencyGaugePercent))
	latencyGauge.BorderStyle = ui.NewStyle(latencyGauge.BarColor)
	latencyGauge.LabelStyle = ui.NewStyle(ui.ColorBlack, latencyGauge.BarColor, ui.ModifierBold)

	operations := widgets.NewTable()
	operations.Title = "Operations"
	operations.Rows = model.OperationRows
	operations.RowSeparator = false
	operations.TextStyle = ui.NewStyle(ui.ColorWhite)
	operations.BorderStyle = ui.NewStyle(ui.ColorCyan)
	operations.RowStyles = map[int]ui.Style{
		0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold),
	}
	for idx, severity := range model.OperationSeverity {
		operations.RowStyles[idx] = ui.NewStyle(colorForSeverity(severity), ui.ColorClear, ui.ModifierBold)
	}

	endpoints := widgets.NewTable()
	endpoints.Title = "Endpoints"
	endpoints.Rows = trimRows(model.EndpointRows, 14)
	endpoints.RowSeparator = false
	endpoints.TextStyle = ui.NewStyle(ui.ColorWhite)
	endpoints.BorderStyle = ui.NewStyle(ui.ColorYellow)
	endpoints.RowStyles = map[int]ui.Style{
		0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow, ui.ModifierBold),
	}
	for idx, severity := range model.EndpointSeverity {
		endpoints.RowStyles[idx] = ui.NewStyle(colorForSeverity(severity), ui.ColorClear, ui.ModifierBold)
	}

	footer := widgets.NewParagraph()
	footer.Title = "Status"
	footer.Text = model.Footer
	footer.BorderStyle = ui.NewStyle(ui.ColorMagenta)
	footer.TextStyle = ui.NewStyle(ui.ColorWhite)

	grid := ui.NewGrid()
	grid.Set(
		ui.NewRow(0.12, header),
		ui.NewRow(0.16,
			ui.NewCol(0.34, health),
			ui.NewCol(0.33, errorGauge),
			ui.NewCol(0.33, latencyGauge),
		),
		ui.NewRow(0.12, sweep),
		ui.NewRow(0.32, operations),
		ui.NewRow(0.20, endpoints),
		ui.NewRow(0.08, footer),
	)

	return grid
}

func trimRows(rows [][]string, max int) [][]string {
	if len(rows) <= max {
		return rows
	}

	head := rows[:1]
	body := rows[1:]
	if len(body) > max-1 {
		body = body[:max-1]
	}
	return append(head, body...)
}

func FormatVerboseLine(opName, nodeName, url string, latency time.Duration, success bool) string {
	status := "FAIL"
	if success {
		status = "OK"
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s %dms %s", status, opName, nodeName, latency.Milliseconds(), url))
}

func ShouldQuitEvent(id string) bool {
	switch id {
	case "q", "Q", "<C-c>":
		return true
	default:
		return false
	}
}

func severityFromState(verdict metrics.Verdict, errorRate float64, p95 time.Duration, thresholds metrics.Thresholds) Severity {
	if verdict != metrics.VerdictStable {
		return SeverityCritical
	}
	if thresholds.MaxErrorRate > 0 && errorRate >= thresholds.MaxErrorRate {
		return SeverityWarn
	}
	if thresholds.MaxP95 > 0 && p95 >= thresholds.MaxP95 {
		return SeverityWarn
	}
	if thresholds.MaxErrorRate > 0 && errorRate >= thresholds.MaxErrorRate*0.5 {
		return SeverityWarn
	}
	if thresholds.MaxP95 > 0 && p95 >= thresholds.MaxP95/2 {
		return SeverityWarn
	}
	return SeverityOK
}

func severityForPercent(percent int) Severity {
	switch {
	case percent >= 100:
		return SeverityCritical
	case percent >= 50:
		return SeverityWarn
	default:
		return SeverityOK
	}
}

func colorForSeverity(severity Severity) ui.Color {
	switch severity {
	case SeverityCritical:
		return ui.ColorRed
	case SeverityWarn:
		return ui.ColorYellow
	default:
		return ui.ColorGreen
	}
}

func clampPercent(v int) int {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	default:
		return v
	}
}
