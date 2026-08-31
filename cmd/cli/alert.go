package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

// alert.go — actions behind the `alert` CLI command group (API mode only).

func requireAPI() error {
	if dbFlag || !apiFlag {
		return fmt.Errorf("alert management requires --api mode (run against osctrl-api)")
	}
	return nil
}

func alertRulesList(ctx context.Context, cmd *cli.Command) error {
	if err := requireAPI(); err != nil {
		return err
	}
	rules, err := osctrlAPI.GetAlertRules()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
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
					return fmt.Errorf("❌ error appending row - %w", err)
				}
			}
		} else {
			fmt.Println("No alert rules")
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("❌ error rendering table - %w", err)
		}
	}
	return nil
}

func ruleToRow(r alertRuleJSON, _ bool) []string {
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
	if err := requireAPI(); err != nil {
		return err
	}
	name := cmd.String("name")
	source := cmd.String("source")
	matchValue := cmd.String("match-value")
	if name == "" || source == "" || matchValue == "" {
		return fmt.Errorf("❌ --name, --source and --match-value are required")
	}
	var channelIDs []uint
	for _, part := range strings.Split(cmd.String("channels"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, strconv.IntSize)
		if err != nil {
			return fmt.Errorf("❌ invalid channel id %q", part)
		}
		channelIDs = append(channelIDs, uint(id))
	}
	rule := alerts.AlertRule{
		Name:            name,
		Source:          source,
		MatchType:       cmd.String("match-type"),
		MatchField:      cmd.String("match-field"),
		MatchValue:      matchValue,
		CooldownMinutes: int(cmd.Int("cooldown")),
		ChannelIDs:      alerts.EncodeChannelIDs(channelIDs),
		Enabled:         cmd.Bool("enabled"),
	}
	if err := osctrlAPI.CreateAlertRule(rule); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	fmt.Printf("✅ Created alert rule %q — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", name)
	return nil
}

func alertRuleDelete(ctx context.Context, cmd *cli.Command) error {
	if err := requireAPI(); err != nil {
		return err
	}
	id := cmd.Uint("id")
	if id == 0 {
		return fmt.Errorf("❌ --id is required")
	}
	if err := osctrlAPI.DeleteAlertRule(id); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	fmt.Printf("✅ Deleted alert rule %d — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", id)
	return nil
}

func alertChannelsList(ctx context.Context, cmd *cli.Command) error {
	if err := requireAPI(); err != nil {
		return err
	}
	channels, err := osctrlAPI.GetAlertChannels()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
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
					return fmt.Errorf("❌ error appending row - %w", err)
				}
			}
		} else {
			fmt.Println("No alert channels")
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("❌ error rendering table - %w", err)
		}
	}
	return nil
}

func channelToRow(c alertChannelJSON) []string {
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
	if err := requireAPI(); err != nil {
		return err
	}
	name := cmd.String("name")
	typ := cmd.String("type")
	configJSON := cmd.String("config")
	if name == "" || typ == "" || configJSON == "" {
		return fmt.Errorf("❌ --name, --type and --config are required")
	}
	if err := alerts.ValidateChannelConfig(typ, configJSON); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	if err := osctrlAPI.CreateAlertChannel(name, typ, configJSON, 0, cmd.Bool("enabled")); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	fmt.Printf("✅ Created alert channel %q — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", name)
	return nil
}

func alertChannelDelete(ctx context.Context, cmd *cli.Command) error {
	if err := requireAPI(); err != nil {
		return err
	}
	id := cmd.Uint("id")
	if id == 0 {
		return fmt.Errorf("❌ --id is required")
	}
	if err := osctrlAPI.DeleteAlertChannel(id); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	fmt.Printf("✅ Deleted alert channel %d — run `osctrl-cli alert apply` to hot-reload osctrl-tls\n", id)
	return nil
}

func alertsApply(ctx context.Context, cmd *cli.Command) error {
	if err := requireAPI(); err != nil {
		return err
	}
	if err := osctrlAPI.ApplyAlerts(); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	fmt.Println("✅ Alert reload requested — osctrl-tls will pick up the changes")
	return nil
}
