package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
	"gorm.io/gorm"
)

// alert.go — actions behind the `alert` CLI command group. DB mode mirrors
// cmd/api/handlers/alerts.go (same field mapping, validation and audit text);
// API mode calls the REST API.

// alertsCommandTTL is how long a queued TLS reload stays valid (the API uses
// the same).
const alertsCommandTTL = 2 * time.Minute

// The alert and service-command managers migrate tables (and may panic or
// exit on failure), so they are built on first use by an alert action and
// never by the shared wrapper. Cached per DB connection.
var (
	alertsMgrConn *gorm.DB
	alertsMgr     *alerts.Manager
	svcCmdsConn   *gorm.DB
	svcCmdsMgr    *servicecommands.Manager
)

func alertsDBManager() (m *alerts.Manager, err error) {
	if db == nil || db.Conn == nil {
		return nil, errors.New("database is not initialised")
	}
	if alertsMgr != nil && alertsMgrConn == db.Conn {
		return alertsMgr, nil
	}
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, fmt.Errorf("error creating alerts manager - %v", r)
		}
	}()
	alertsMgr, alertsMgrConn = alerts.NewManager(db.Conn), db.Conn
	return alertsMgr, nil
}

func serviceCommandsDBManager() (*servicecommands.Manager, error) {
	if db == nil || db.Conn == nil {
		return nil, errors.New("database is not initialised")
	}
	if svcCmdsMgr == nil || svcCmdsConn != db.Conn {
		// NewManager log.Fatals on a migration failure: migrate first so the
		// failure is returned instead
		if err := db.Conn.AutoMigrate(&servicecommands.ServiceCommand{}); err != nil {
			return nil, fmt.Errorf("error migrating service commands table - %w", err)
		}
		svcCmdsMgr, svcCmdsConn = servicecommands.NewManager(db.Conn), db.Conn
	}
	return svcCmdsMgr, nil
}

// alertRuleToJSON is the API's alert rule DTO for a stored rule.
func alertRuleToJSON(r alerts.AlertRule) apiclient.AlertRuleJSON {
	return apiclient.AlertRuleJSON{
		ID: r.ID, Name: r.Name, EnvironmentID: r.EnvironmentID, Source: r.Source, NodeUUID: r.NodeUUID,
		MatchType: r.MatchType, MatchField: r.MatchField, MatchValue: r.MatchValue,
		StatusSeverity: r.StatusSeverity, VulnMinSeverity: r.VulnMinSeverity, CooldownMinutes: r.CooldownMinutes,
		ChannelIDs: alerts.DecodeChannelIDsOrEmpty(r.ChannelIDs), Enabled: r.Enabled, Info: r.Info,
	}
}

// alertChannelToJSON is the API's channel DTO with secrets redacted, as the
// API lists channels without reveal=1.
func alertChannelToJSON(c alerts.AlertChannel) apiclient.AlertChannelJSON {
	return apiclient.AlertChannelJSON{
		ID: c.ID, Name: c.Name, EnvironmentID: c.EnvironmentID, Type: c.Type, Enabled: c.Enabled,
		Config: json.RawMessage(alerts.RedactedChannelConfig(c.Type, c.Config)), Info: c.Info,
	}
}

func alertAudit(text string) {
	auditlogsmgr.SettingsAction(getShellUsername(), text, "CLI")
}

func alertRulesList(ctx context.Context, cmd *cli.Command) error {
	var envID *uint
	if cmd.IsSet("environment") {
		id := cmd.Uint("environment")
		envID = &id
	}
	rules := []apiclient.AlertRuleJSON{}
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		rows, err := mgr.ListRules(envID)
		if err != nil {
			return fmt.Errorf("error listing alert rules - %w", err)
		}
		for _, row := range rows {
			rules = append(rules, alertRuleToJSON(row))
		}
	} else if apiFlag {
		var err error
		if rules, err = osctrlAPI.GetAlertRules(envID); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	header := []string{"ID", "Name", "Env", "Source", "Match", "Field", "Pattern", "Cooldown", "Channels", "Enabled"}
	switch formatFlag {
	case jsonFormat:
		raw, err := json.Marshal(rules)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(raw))
	case csvFormat:
		data := [][]string{header}
		for _, r := range rules {
			data = append(data, ruleToRow(r, false))
		}
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(rules) > 0 {
			fmt.Printf("Existing alert rules (%d):\n", len(rules))
			for _, r := range rules {
				if err := table.Append(ruleToRow(r, true)); err != nil {
					return fmt.Errorf("error appending row - %w", err)
				}
			}
		} else {
			fmt.Println("No alert rules")
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func ruleToRow(r apiclient.AlertRuleJSON, _ bool) []string {
	return []string{
		strconv.FormatUint(uint64(r.ID), 10),
		r.Name,
		strconv.FormatUint(uint64(r.EnvironmentID), 10),
		r.Source,
		r.MatchType,
		r.MatchField,
		r.MatchValue,
		strconv.Itoa(r.CooldownMinutes),
		strings.Join(uintsToStrings(r.ChannelIDs), ","),
		boolTag(r.Enabled),
	}
}

func uintsToStrings(ids []uint) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.FormatUint(uint64(id), 10))
	}
	return out
}

func alertRuleCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	source := cmd.String("source")
	matchValue := cmd.String("match-value")
	// Node-state and vulnerability rules do no pattern matching.
	noPattern := source == alerts.SourceNodeInactive || source == alerts.SourceNodeRecovered || source == alerts.SourceVulnFinding
	if name == "" || source == "" {
		return fmt.Errorf("--name and --source are required")
	}
	if matchValue == "" && !noPattern {
		return fmt.Errorf("--match-value is required unless the source is node_inactive, node_recovered or vuln_finding")
	}
	var channelIDs []uint
	for _, part := range strings.Split(cmd.String("channels"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("invalid channel id %q", part)
		}
		channelIDs = append(channelIDs, uint(id))
	}
	rule := alerts.AlertRule{
		Name:            name,
		EnvironmentID:   cmd.Uint("environment"),
		Source:          source,
		NodeUUID:        strings.TrimSpace(cmd.String("node-uuid")),
		MatchType:       cmd.String("match-type"),
		MatchField:      cmd.String("match-field"),
		MatchValue:      matchValue,
		StatusSeverity:  cmd.String("status-severity"),
		VulnMinSeverity: cmd.String("vuln-min-severity"),
		CooldownMinutes: int(cmd.Int("cooldown")),
		ChannelIDs:      alerts.EncodeChannelIDs(channelIDs),
		Enabled:         cmd.Bool("enabled"),
		Info:            cmd.String("info"),
	}
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		row, err := mgr.CreateRule(rule)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		alertAudit(fmt.Sprintf("created alert rule %q (source %s, env %d)", row.Name, row.Source, row.EnvironmentID))
		if row.Source == alerts.SourceVulnFinding {
			fmt.Println("ℹ️  --db mode does not check that vulnerability monitoring is enabled (--vuln-enabled): the rule never fires without it")
		}
	} else if apiFlag {
		if err := osctrlAPI.CreateAlertRule(rule); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	fmt.Printf("✅ Created alert rule %q — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", name)
	return nil
}

func alertRuleDelete(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Uint("id")
	if id == 0 {
		return fmt.Errorf("--id is required")
	}
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		if err := mgr.DeleteRule(id); err != nil {
			return fmt.Errorf("%w", err)
		}
		alertAudit(fmt.Sprintf("deleted alert rule %d", id))
	} else if apiFlag {
		if err := osctrlAPI.DeleteAlertRule(id); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	fmt.Printf("✅ Deleted alert rule %d — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", id)
	return nil
}

func alertChannelsList(ctx context.Context, cmd *cli.Command) error {
	channels := []apiclient.AlertChannelJSON{}
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		rows, err := mgr.ListChannels(nil)
		if err != nil {
			return fmt.Errorf("error listing alert channels - %w", err)
		}
		for _, row := range rows {
			channels = append(channels, alertChannelToJSON(row))
		}
	} else if apiFlag {
		var err error
		if channels, err = osctrlAPI.GetAlertChannels(); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	header := []string{"ID", "Name", "Env", "Type", "Enabled", "Config"}
	switch formatFlag {
	case jsonFormat:
		raw, err := json.Marshal(channels)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(raw))
	case csvFormat:
		data := [][]string{header}
		for _, c := range channels {
			data = append(data, channelToRow(c))
		}
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(channels) > 0 {
			fmt.Printf("Existing alert channels (%d):\n", len(channels))
			for _, c := range channels {
				if err := table.Append(channelToRow(c)); err != nil {
					return fmt.Errorf("error appending row - %w", err)
				}
			}
		} else {
			fmt.Println("No alert channels")
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func channelToRow(c apiclient.AlertChannelJSON) []string {
	return []string{
		strconv.FormatUint(uint64(c.ID), 10),
		c.Name,
		strconv.FormatUint(uint64(c.EnvironmentID), 10),
		c.Type,
		boolTag(c.Enabled),
		string(c.Config),
	}
}

func alertChannelCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	typ := cmd.String("type")
	configJSON := cmd.String("config")
	if name == "" || typ == "" || configJSON == "" {
		return fmt.Errorf("--name, --type and --config are required")
	}
	if err := alerts.ValidateChannelConfig(typ, configJSON); err != nil {
		return fmt.Errorf("%w", err)
	}
	envID := cmd.Uint("environment")
	// The config (secrets) is never printed or audited, only the name.
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		row, err := mgr.CreateChannel(alerts.AlertChannel{
			Name: name, EnvironmentID: envID, Type: typ, Enabled: cmd.Bool("enabled"), Config: configJSON, Info: cmd.String("info"),
		})
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		alertAudit(fmt.Sprintf("created alert channel %q (type %s, env %d)", row.Name, row.Type, row.EnvironmentID))
	} else if apiFlag {
		if err := osctrlAPI.CreateAlertChannel(name, typ, configJSON, cmd.String("info"), envID, cmd.Bool("enabled")); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	fmt.Printf("✅ Created alert channel %q — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", name)
	return nil
}

func alertChannelDelete(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Uint("id")
	if id == 0 {
		return fmt.Errorf("--id is required")
	}
	if dbFlag {
		mgr, err := alertsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		if err := mgr.DeleteChannel(id); err != nil {
			return fmt.Errorf("%w", err)
		}
		alertAudit(fmt.Sprintf("deleted alert channel %d", id))
	} else if apiFlag {
		if err := osctrlAPI.DeleteAlertChannel(id); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	fmt.Printf("✅ Deleted alert channel %d — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", id)
	return nil
}

func alertsApply(ctx context.Context, cmd *cli.Command) error {
	if dbFlag {
		mgr, err := serviceCommandsDBManager()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		queued, err := mgr.Request(config.ServiceTLS, servicecommands.ActionReloadAlerts, getShellUsername(), "CLI", alertsCommandTTL)
		if err != nil {
			return fmt.Errorf("error requesting tls alerts reload - %w", err)
		}
		alertAudit(fmt.Sprintf("apply alerts reload command %s", queued.CommandID))
	} else if apiFlag {
		if err := osctrlAPI.ApplyAlerts(); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	fmt.Println("✅ Alert reload requested — osctrl-tls will pick up the changes")
	return nil
}
