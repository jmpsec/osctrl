package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/stretchr/testify/require"
)

const (
	alertWebhookSecretURL = "https://hooks.example.com/services/TOPSECRETPATH"
	alertWebhookHMAC      = "hmac-top-secret-value"
	alertSMTPPassword     = "smtp-password-s3cret"
)

func alertRuleList(t *testing.T, run func(...string) (string, error), extra ...string) []apiclient.AlertRuleJSON {
	t.Helper()
	out, err := run(append([]string{"-o", "json", "alert", "rules"}, extra...)...)
	require.NoError(t, err)
	var rules []apiclient.AlertRuleJSON
	require.NoError(t, json.Unmarshal([]byte(out), &rules))
	return rules
}

func TestAlertRulesParity(t *testing.T) {
	rig := newParityRig(t)
	env, err := rig.Envs.Get("dev")
	require.NoError(t, err)
	envID := string(rune('0' + env.ID))
	create := func(run func(...string) (string, error), name string) {
		out, err := run("alert", "rule-create", "--name", name, "--source", "result_log", "--match-value", "evil",
			"--match-field", "name", "--cooldown", "5", "--environment", envID)
		require.NoError(t, err)
		require.Contains(t, out, name)
	}
	create(rig.RunDB, "rule-db")
	create(rig.RunAPI, "rule-api")
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		rules := alertRuleList(t, run)
		require.Len(t, rules, 2)
		byName := map[string]apiclient.AlertRuleJSON{}
		for _, r := range rules {
			byName[r.Name] = r
		}
		a, b := byName["rule-db"], byName["rule-api"]
		require.NotZero(t, a.ID)
		require.NotZero(t, b.ID)
		a.ID, a.Name, b.ID, b.Name = 0, "", 0, ""
		require.Equal(t, a, b)
		require.Equal(t, "result_log", a.Source)
		require.Equal(t, "evil", a.MatchValue)
		require.Equal(t, 5, a.CooldownMinutes)
		require.Equal(t, env.ID, a.EnvironmentID)
		require.True(t, a.Enabled)
		// The env filter reaches both modes.
		require.Len(t, alertRuleList(t, run, "--environment", envID), 2)
		require.Empty(t, alertRuleList(t, run, "--environment", "9"))
	}
	// Delete: one per mode, both gone in both views.
	_, err = rig.RunDB("alert", "rule-delete", "--id", "1")
	require.NoError(t, err)
	_, err = rig.RunAPI("alert", "rule-delete", "--id", "2")
	require.NoError(t, err)
	require.Empty(t, alertRuleList(t, rig.RunDB))
	require.Empty(t, alertRuleList(t, rig.RunAPI))
	// Missing rule: an error in both modes.
	_, err = rig.RunDB("alert", "rule-delete", "--id", "77")
	require.ErrorIs(t, err, alerts.ErrRuleNotFound)
	_, err = rig.RunAPI("alert", "rule-delete", "--id", "77")
	require.Error(t, err)
}

func TestAlertRuleNewFlagsPropagate(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		name := []string{"db", "api"}[i]
		_, err := run("alert", "rule-create", "--name", name, "--source", "status_log", "--match-value", "x",
			"--environment", "1", "--node-uuid", " NODE-1 ", "--status-severity", "error", "--info", "why "+name)
		require.NoError(t, err)
	}
	// The API refuses vuln_finding without vulnerability monitoring (the rig
	// has none), so only DB mode can store one here.
	_, err := rig.RunDB("alert", "rule-create", "--name", "vdb", "--source", "vuln_finding", "--vuln-min-severity", "kev")
	require.NoError(t, err)
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		rules := alertRuleList(t, run)
		require.Len(t, rules, 3)
		for _, r := range rules {
			switch r.Name {
			case "db", "api":
				require.Equal(t, uint(1), r.EnvironmentID)
				require.Equal(t, "NODE-1", r.NodeUUID)
				require.Equal(t, "error", r.StatusSeverity)
				require.Equal(t, "why "+r.Name, r.Info)
			default:
				require.Equal(t, "kev", r.VulnMinSeverity)
			}
		}
	}
}

func TestAlertRuleCreateInvalidIsErrorNotExit(t *testing.T) {
	rig := newParityRig(t)
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		_, err := run("alert", "rule-create", "--name", "x")
		require.ErrorContains(t, err, "required")
		_, err = run("alert", "rule-create", "--name", "x", "--source", "result_log")
		require.ErrorContains(t, err, "--match-value is required unless the source is node_inactive")
		_, err = run("alert", "rule-create", "--name", "x", "--source", "bogus", "--match-value", "v")
		require.Error(t, err)
		_, err = run("alert", "rule-create", "--name", "x", "--source", "result_log", "--match-value", "v", "--channels", "a")
		require.ErrorContains(t, err, "invalid channel id")
		_, err = run("alert", "rule-delete")
		require.ErrorContains(t, err, "--id is required")
		_, err = run("alert", "channel-create", "--name", "c", "--type", "webhook", "--config", `{"url":`)
		require.Error(t, err)
	}
}

func TestAlertVulnFindingNoteOnlyInDBMode(t *testing.T) {
	rig := newParityRig(t)
	out, err := rig.RunDB("alert", "rule-create", "--name", "v", "--source", "vuln_finding", "--vuln-min-severity", "any")
	require.NoError(t, err)
	require.Contains(t, out, "vulnerability monitoring")
	out, err = rig.RunDB("alert", "rule-create", "--name", "plain", "--source", "result_log", "--match-value", "x")
	require.NoError(t, err)
	require.NotContains(t, out, "vulnerability monitoring")
}

func createWebhookAndEmail(t *testing.T, rig *parityRig, run func(...string) (string, error), suffix string) string {
	t.Helper()
	var all string
	out, err := run("alert", "channel-create", "--name", "hook"+suffix, "--type", "webhook",
		"--config", `{"url":"`+alertWebhookSecretURL+`","secret":"`+alertWebhookHMAC+`"}`)
	require.NoError(t, err)
	all += out
	out, err = run("alert", "channel-create", "--name", "mail"+suffix, "--type", "email",
		"--config", `{"host":"smtp.example.com","port":587,"username":"u","password":"`+alertSMTPPassword+`","from":"a@example.com","to":"b@example.com"}`)
	require.NoError(t, err)
	return all + out
}

func TestAlertChannelCreateDoesNotEchoConfig(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		out := createWebhookAndEmail(t, rig, run, []string{"-db", "-api"}[i])
		for _, secret := range []string{alertWebhookSecretURL, alertWebhookHMAC, alertSMTPPassword, "TOPSECRETPATH"} {
			require.NotContains(t, out, secret)
		}
		// A rejected config does not echo it either.
		_, err := run("alert", "channel-create", "--name", "bad", "--type", "webhook", "--config", `{"url":123,"secret":"`+alertWebhookHMAC+`"}`)
		require.Error(t, err)
		require.NotContains(t, err.Error(), alertWebhookHMAC)
	}
	var texts []string
	var entries []auditlog.AuditLog
	require.NoError(t, rig.DB.Find(&entries).Error)
	for _, e := range entries {
		texts = append(texts, e.Line)
	}
	all := strings.Join(texts, "\n")
	for _, secret := range []string{alertWebhookSecretURL, alertWebhookHMAC, alertSMTPPassword} {
		require.NotContains(t, all, secret)
	}
}

func TestAlertChannelListRedactedInBothModes(t *testing.T) {
	rig := newParityRig(t)
	createWebhookAndEmail(t, rig, rig.RunDB, "-db")
	createWebhookAndEmail(t, rig, rig.RunAPI, "-api")
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		var outs []string
		for _, format := range []string{"json", "csv", "pretty"} {
			out, err := run("-o", format, "alert", "channels")
			require.NoError(t, err)
			outs = append(outs, out)
			// The registry redacts every secret field: the webhook URL
			// (a bearer secret), the HMAC secret and the SMTP password.
			for _, secret := range []string{alertWebhookSecretURL, "TOPSECRETPATH", alertWebhookHMAC, alertSMTPPassword} {
				require.NotContains(t, out, secret, format)
			}
			require.Contains(t, out, "hook-db", format)
			require.Contains(t, out, "mail-api", format)
		}
		var chans []apiclient.AlertChannelJSON
		require.NoError(t, json.Unmarshal([]byte(outs[0]), &chans))
		require.Len(t, chans, 4)
	}
	// Same rows both ways.
	dbOut, err := rig.RunDB("-o", "json", "alert", "channels")
	require.NoError(t, err)
	apiOut, err := rig.RunAPI("-o", "json", "alert", "channels")
	require.NoError(t, err)
	var a, b []apiclient.AlertChannelJSON
	require.NoError(t, json.Unmarshal([]byte(dbOut), &a))
	require.NoError(t, json.Unmarshal([]byte(apiOut), &b))
	require.Equal(t, len(a), len(b))
	for i := range a {
		require.Equal(t, a[i].Type, b[i].Type)
		require.JSONEq(t, string(a[i].Config), string(b[i].Config))
	}
	// The stored row is untouched by redaction.
	var row alerts.AlertChannel
	require.NoError(t, rig.DB.First(&row, 1).Error)
	require.Contains(t, row.Config, alertWebhookSecretURL)
}

func TestAlertChannelEnvironmentAndDelete(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		_, err := run("alert", "channel-create", "--name", "c"+string(rune('a'+i)), "--type", "webhook",
			"--config", `{"url":"https://example.com/h"}`, "--environment", "1", "--enabled=false")
		require.NoError(t, err)
	}
	for _, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		out, err := run("-o", "json", "alert", "channels")
		require.NoError(t, err)
		var chans []apiclient.AlertChannelJSON
		require.NoError(t, json.Unmarshal([]byte(out), &chans))
		require.Len(t, chans, 2)
		for _, c := range chans {
			require.Equal(t, uint(1), c.EnvironmentID)
			require.False(t, c.Enabled)
		}
	}
	_, err := rig.RunDB("alert", "channel-delete", "--id", "1")
	require.NoError(t, err)
	_, err = rig.RunAPI("alert", "channel-delete", "--id", "2")
	require.NoError(t, err)
	var n int64
	require.NoError(t, rig.DB.Model(&alerts.AlertChannel{}).Count(&n).Error)
	require.Zero(t, n)
	_, err = rig.RunDB("alert", "channel-delete", "--id", "1")
	require.ErrorIs(t, err, alerts.ErrChannelNotFound)
}

func TestAlertApplyQueuesReloadInDBMode(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		_, err := run("alert", "apply")
		require.NoError(t, err)
		var cmds []servicecommands.ServiceCommand
		require.NoError(t, rig.DB.Where("action = ?", servicecommands.ActionReloadAlerts).Find(&cmds).Error)
		require.Len(t, cmds, i+1)
		require.Equal(t, config.ServiceTLS, cmds[i].TargetService)
		// Same TTL as the API (alertsCommandTTL)
		require.WithinDuration(t, time.Now().Add(alertsCommandTTL), cmds[i].ExpiresAt, 30*time.Second)
		var entries []auditlog.AuditLog
		require.NoError(t, rig.DB.Find(&entries).Error)
		found := false
		for _, e := range entries {
			found = found || strings.HasSuffix(e.Line, "apply alerts reload command "+cmds[i].CommandID)
		}
		require.True(t, found, "audit entry for command %s", cmds[i].CommandID)
	}
}

func TestAlertChannelCreateInfo(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		_, err := run("alert", "channel-create", "--name", fmt.Sprint("c", i), "--type", "webhook", "--config", `{"url":"https://example.com/h"}`, "--info", "about it")
		require.NoError(t, err)
		var ch alerts.AlertChannel
		require.NoError(t, rig.DB.Where("id = ?", i+1).First(&ch).Error)
		require.Equal(t, "about it", ch.Info)
	}
}

func TestAlertAuditEntryWritten(t *testing.T) {
	rig := newParityRig(t)
	for i, run := range []func(...string) (string, error){rig.RunDB, rig.RunAPI} {
		n := []string{"a", "b"}[i]
		_, err := run("alert", "rule-create", "--name", "r"+n, "--source", "result_log", "--match-value", "x", "--environment", "1")
		require.NoError(t, err)
		_, err = run("alert", "channel-create", "--name", "c"+n, "--type", "webhook", "--config", `{"url":"https://example.com/h"}`)
		require.NoError(t, err)
	}
	_, err := rig.RunDB("alert", "rule-delete", "--id", "1")
	require.NoError(t, err)
	_, err = rig.RunAPI("alert", "rule-delete", "--id", "2")
	require.NoError(t, err)
	_, err = rig.RunDB("alert", "channel-delete", "--id", "1")
	require.NoError(t, err)
	_, err = rig.RunAPI("alert", "channel-delete", "--id", "2")
	require.NoError(t, err)
	var lines []string
	var entries []auditlog.AuditLog
	require.NoError(t, rig.DB.Find(&entries).Error)
	for _, e := range entries {
		lines = append(lines, e.Line)
	}
	for i, l := range lines {
		if _, rest, ok := strings.Cut(l, " performed settings action: "); ok {
			lines[i] = rest
		}
	}
	for _, want := range []string{
		`created alert rule "ra" (source result_log, env 1)`,
		`created alert rule "rb" (source result_log, env 1)`,
		`created alert channel "ca" (type webhook, env 0)`,
		`created alert channel "cb" (type webhook, env 0)`,
		`deleted alert rule 1`,
		`deleted alert rule 2`,
		`deleted alert channel 1`,
		`deleted alert channel 2`,
	} {
		require.Contains(t, lines, want)
	}
	// One entry per action.
	count := map[string]int{}
	for _, l := range lines {
		count[l]++
	}
	require.Equal(t, 1, count[`created alert rule "ra" (source result_log, env 1)`])
}

func TestAlertManagersNotBuiltByWrapper(t *testing.T) {
	rig := newParityRig(t)
	require.NoError(t, rig.DB.Migrator().DropTable(&alerts.AlertRule{}, &alerts.AlertChannel{}, &alerts.AlertHistory{}, &servicecommands.ServiceCommand{}))
	_, err := rig.RunDB("env", "list")
	require.NoError(t, err)
	for _, m := range []any{&alerts.AlertRule{}, &alerts.AlertChannel{}, &alerts.AlertHistory{}, &servicecommands.ServiceCommand{}} {
		require.False(t, rig.DB.Migrator().HasTable(m), "%T was created by the shared wrapper", m)
	}
	// The alert commands build them on demand.
	_, err = rig.RunDB("alert", "rules")
	require.NoError(t, err)
	require.True(t, rig.DB.Migrator().HasTable(&alerts.AlertRule{}))
}

func TestAlertAPIForbiddenForNonAdmin(t *testing.T) {
	rig := newParityRig(t)
	token := rig.SeedUser("bob", false)
	for _, args := range [][]string{{"alert", "rules"}, {"alert", "channels"}, {"alert", "apply"}, {"alert", "rule-delete", "--id", "1"}} {
		_, err := rig.RunAPIAs(token, args...)
		require.ErrorContains(t, err, "403", strings.Join(args, " "))
	}
}
