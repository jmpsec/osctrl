package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/urfave/cli/v3"
)

// tui_dashboard.go — full-screen TUI dashboard (osctrl-cli tui).
//
// Renders a live view of the deployment using termui: fleet gauges,
// platform breakdown, and a detail pane switchable between environments,
// recent queries, and the audit log. Data comes from the same DataStore
// the interactive shell uses, so it works in both --api and --db modes.
//
// Keys: q / Ctrl-C quit · r refresh · 1 environments · 2 queries · 3 audit.

const tuiRefreshSeconds = 30

const (
	paneEnvironments = iota
	paneQueries
	paneAudit
)

// tuiModel holds the dashboard state between refreshes.
type tuiModel struct {
	store DataStore
	pane  int

	stats tuiStats
	audit []auditRow

	footer *widgets.Paragraph
}

// runTUIDashboard is the action behind the `tui` CLI command.
func runTUIDashboard(cctx context.Context, cmd *cli.Command) error {
	var store DataStore
	switch {
	case dbFlag:
		store = newDBStore()
	case apiFlag:
		store = newAPIStore(osctrlAPI)
	default:
		return fmt.Errorf("enable --db or --api to use the dashboard")
	}
	if dbFlag {
		if err := db.Check(); err != nil {
			return fmt.Errorf("db check: %w", err)
		}
	} else {
		if err := osctrlAPI.CheckAPI(); err != nil {
			return fmt.Errorf("api check: %w", err)
		}
	}
	model := &tuiModel{store: store}
	if err := model.refresh(); err != nil {
		return err
	}
	return model.loop()
}

func (m *tuiModel) loop() error {
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	grid := m.render()
	ui.Render(grid)

	events := ui.PollEvents()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	remaining := tuiRefreshSeconds
	for {
		select {
		case e := <-events:
			switch e.ID {
			case "q", "<C-c>":
				return nil
			case "r":
				if err := m.refresh(); err != nil {
					return err
				}
				remaining = tuiRefreshSeconds
			case "1":
				m.pane = paneEnvironments
			case "2":
				m.pane = paneQueries
			case "3":
				m.pane = paneAudit
			case "<Resize>":
			}
			ui.Clear()
			grid = m.render()
			ui.Render(grid)
		case <-ticker.C:
			remaining--
			if remaining <= 0 {
				if err := m.refresh(); err != nil {
					return err
				}
				remaining = tuiRefreshSeconds
			}
			ui.Clear()
			grid = m.render()
			ui.Render(grid)
		}
	}
}

// refresh pulls the latest snapshot from the store.
func (m *tuiModel) refresh() error {
	stats, err := m.store.Stats()
	if err != nil {
		return err
	}
	m.stats = stats
	// Audit pane is optional: some deployments disable the audit log.
	if audit, err := m.store.AuditLogs(); err == nil {
		m.audit = audit
	}
	return nil
}

// footerText renders the bottom help bar.
func (m *tuiModel) footerText(remaining int) string {
	return fmt.Sprintf(" [1] environments  [2] queries  [3] audit  [r] refresh  [q] quit · next refresh in %ds ", remaining)
}

// render builds the grid for the current state.
func (m *tuiModel) render() *ui.Grid {
	header := widgets.NewParagraph()
	header.Title = " 🛡  osctrl-cli dashboard "
	header.Text = fmt.Sprintf(" v%s · %s mode · %s ", version.OsctrlVersion, m.store.Mode(), time.Now().Format("15:04:05"))
	header.BorderStyle = ui.NewStyle(ui.ColorCyan)
	header.TextStyle = ui.NewStyle(ui.ColorWhite, ui.ColorClear, ui.ModifierBold)

	// Fleet health gauge: percentage of nodes active.
	activePercent := 0
	if m.stats.TotalNodes > 0 {
		activePercent = int(float64(m.stats.ActiveNodes) / float64(m.stats.TotalNodes) * 100)
	}
	fleet := widgets.NewGauge()
	fleet.Title = fmt.Sprintf(" Fleet health — %d/%d active ", m.stats.ActiveNodes, m.stats.TotalNodes)
	fleet.Percent = activePercent
	fleetColor := ui.ColorGreen
	switch {
	case activePercent < 50:
		fleetColor = ui.ColorRed
	case activePercent < 80:
		fleetColor = ui.ColorYellow
	}
	fleet.BarColor = fleetColor
	fleet.BorderStyle = ui.NewStyle(fleetColor)
	fleet.LabelStyle = ui.NewStyle(ui.ColorBlack, fleetColor, ui.ModifierBold)

	// Activity gauge: queries + carves in flight.
	workload := widgets.NewGauge()
	workload.Title = fmt.Sprintf(" In flight — %d queries · %d carves ", m.stats.TotalActiveQueries, m.stats.TotalActiveCarves)
	workloadPercent := (m.stats.TotalActiveQueries + m.stats.TotalActiveCarves) % 101
	workload.Percent = workloadPercent
	workload.BarColor = ui.ColorMagenta
	workload.BorderStyle = ui.NewStyle(ui.ColorMagenta)
	workload.LabelStyle = ui.NewStyle(ui.ColorBlack, ui.ColorMagenta, ui.ModifierBold)

	// Platform breakdown.
	platforms := widgets.NewBarChart()
	platforms.Title = " Platforms "
	platforms.Data = []float64{
		float64(m.stats.Platforms.Linux),
		float64(m.stats.Platforms.Darwin),
		float64(m.stats.Platforms.Windows),
		float64(m.stats.Platforms.Other),
	}
	platforms.Labels = []string{"linux", "darwin", "win", "other"}
	platforms.BarColors = []ui.Color{ui.ColorCyan, ui.ColorCyan, ui.ColorCyan, ui.ColorWhite}
	platforms.LabelStyles = []ui.Style{ui.NewStyle(ui.ColorWhite)}
	platforms.NumStyles = []ui.Style{ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)}
	platforms.BorderStyle = ui.NewStyle(ui.ColorCyan)

	// Detail pane.
	var detail *widgets.Table
	var paneTitle string
	switch m.pane {
	case paneQueries:
		paneTitle = " Active queries by environment "
		detail = m.queriesTable()
	case paneAudit:
		paneTitle = " Recent audit entries "
		detail = m.auditTable()
	default:
		paneTitle = " Environments "
		detail = m.environmentsTable()
	}
	detail.Title = paneTitle
	detail.BorderStyle = ui.NewStyle(ui.ColorYellow)
	detail.TextStyle = ui.NewStyle(ui.ColorWhite)
	detail.RowSeparator = false
	detail.RowStyles = map[int]ui.Style{
		0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow, ui.ModifierBold),
	}

	footer := widgets.NewParagraph()
	footer.Text = m.footerText(tuiRefreshSeconds)
	footer.BorderStyle = ui.NewStyle(ui.ColorMagenta)
	footer.TextStyle = ui.NewStyle(ui.ColorWhite)
	m.footer = footer

	grid := ui.NewGrid()
	grid.Set(
		ui.NewRow(1.0/10.0, header),
		ui.NewRow(2.0/10.0,
			ui.NewCol(0.5, fleet),
			ui.NewCol(0.5, workload),
		),
		ui.NewRow(3.0/10.0, platforms),
		ui.NewRow(3.0/10.0, detail),
		ui.NewRow(1.0/10.0, footer),
	)
	return grid
}

// environmentsTable renders per-env node/query/carve counts.
func (m *tuiModel) environmentsTable() *widgets.Table {
	t := widgets.NewTable()
	rows := [][]string{{"Env", "Active", "Inactive", "Total", "Queries", "Carves"}}
	envs := make([]tuiEnvStats, len(m.stats.Environments))
	copy(envs, m.stats.Environments)
	sort.Slice(envs, func(i, j int) bool { return envs[i].Name < envs[j].Name })
	for _, e := range envs {
		rows = append(rows, []string{
			e.Name,
			strconv.FormatInt(e.Active, 10),
			strconv.FormatInt(e.Inactive, 10),
			strconv.FormatInt(e.Total, 10),
			strconv.Itoa(e.ActiveQueries),
			strconv.Itoa(e.ActiveCarves),
		})
	}
	t.Rows = rows
	return t
}

// queriesTable shows the summary line for query activity per env.
func (m *tuiModel) queriesTable() *widgets.Table {
	t := widgets.NewTable()
	rows := [][]string{{"Env", "Active queries", "Active carves", "Linux", "Darwin", "Windows"}}
	envs := make([]tuiEnvStats, len(m.stats.Environments))
	copy(envs, m.stats.Environments)
	sort.Slice(envs, func(i, j int) bool { return envs[i].Name < envs[j].Name })
	for _, e := range envs {
		rows = append(rows, []string{
			e.Name,
			strconv.Itoa(e.ActiveQueries),
			strconv.Itoa(e.ActiveCarves),
			strconv.FormatInt(e.Platforms.Linux, 10),
			strconv.FormatInt(e.Platforms.Darwin, 10),
			strconv.FormatInt(e.Platforms.Windows, 10),
		})
	}
	t.Rows = rows
	return t
}

// auditTable renders the most recent audit entries (newest first, capped).
func (m *tuiModel) auditTable() *widgets.Table {
	t := widgets.NewTable()
	rows := [][]string{{"When", "User", "Type", "Entry"}}
	entries := make([]auditRow, len(m.audit))
	copy(entries, m.audit)
	// audit rows arrive newest-first from the API; show the top slice.
	const cap = 20
	if len(entries) > cap {
		entries = entries[:cap]
	}
	for _, a := range entries {
		line := a.Line
		if len(line) > 60 {
			line = line[:57] + "..."
		}
		rows = append(rows, []string{a.When, a.Username, a.LogType, line})
	}
	t.Rows = rows
	return t
}
