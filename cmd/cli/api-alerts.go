package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/alerts"
)

// api-alerts.go — REST wrappers for the alerts management API.
//
// Routes:
//   GET    /api/v1/alerts/rules[?env={id}]
//   GET    /api/v1/alerts/rules/{id}
//   POST   /api/v1/alerts/rules
//   PUT    /api/v1/alerts/rules/{id}
//   DELETE /api/v1/alerts/rules/{id}
//   GET    /api/v1/alerts/channels[?env={id}&reveal={0|1}]
//   GET    /api/v1/alerts/channels/types
//   GET    /api/v1/alerts/channels/{id}
//   POST   /api/v1/alerts/channels
//   PUT    /api/v1/alerts/channels/{id}
//   DELETE /api/v1/alerts/channels/{id}
//   GET    /api/v1/alerts/history[?limit={n}]
//   POST   /api/v1/alerts/apply

// alertRuleJSON mirrors the API DTO.
type alertRuleJSON struct {
	ID              uint   `json:"id"`
	Name            string `json:"name"`
	EnvironmentID   uint   `json:"environment_id"`
	Source          string `json:"source"`
	MatchType       string `json:"match_type"`
	MatchField      string `json:"match_field"`
	MatchValue      string `json:"match_value"`
	StatusSeverity  string `json:"status_severity"`
	CooldownMinutes int    `json:"cooldown_minutes"`
	ChannelIDs      []uint `json:"channel_ids"`
	Enabled         bool   `json:"enabled"`
	Info            string `json:"info"`
}

// alertChannelJSON mirrors the API DTO (config decoded).
type alertChannelJSON struct {
	ID            uint            `json:"id"`
	Name          string          `json:"name"`
	EnvironmentID uint            `json:"environment_id"`
	Type          string          `json:"type"`
	Enabled       bool            `json:"enabled"`
	Config        json.RawMessage `json:"config"`
	Info          string          `json:"info"`
}

// GetAlertRules lists alert rules.
func (api *OsctrlAPI) GetAlertRules() ([]alertRuleJSON, error) {
	var rules []alertRuleJSON
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "rules"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return rules, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return rules, fmt.Errorf("can not parse body - %w", err)
	}
	return rules, nil
}

// CreateAlertRule creates an alert rule.
func (api *OsctrlAPI) CreateAlertRule(rule alerts.AlertRule) error {
	body := struct {
		Name            string `json:"name"`
		EnvironmentID   uint   `json:"environment_id"`
		Source          string `json:"source"`
		MatchType       string `json:"match_type"`
		MatchField      string `json:"match_field,omitempty"`
		MatchValue      string `json:"match_value"`
		StatusSeverity  string `json:"status_severity,omitempty"`
		CooldownMinutes int    `json:"cooldown_minutes,omitempty"`
		ChannelIDs      []uint `json:"channel_ids,omitempty"`
		Enabled         bool   `json:"enabled"`
		Info            string `json:"info,omitempty"`
	}{
		Name: rule.Name, EnvironmentID: rule.EnvironmentID, Source: rule.Source,
		MatchType: rule.MatchType, MatchField: rule.MatchField, MatchValue: rule.MatchValue,
		StatusSeverity: rule.StatusSeverity, CooldownMinutes: rule.CooldownMinutes,
		ChannelIDs: alerts.DecodeChannelIDsOrEmpty(rule.ChannelIDs), Enabled: rule.Enabled, Info: rule.Info,
	}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "rules"))
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// DeleteAlertRule removes an alert rule by ID.
func (api *OsctrlAPI) DeleteAlertRule(id uint) error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "rules", strconv.FormatUint(uint64(id), 10)))
	raw, err := api.ReqGeneric("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// GetAlertChannels lists alert channels.
func (api *OsctrlAPI) GetAlertChannels() ([]alertChannelJSON, error) {
	var channels []alertChannelJSON
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "channels"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return channels, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &channels); err != nil {
		return channels, fmt.Errorf("can not parse body - %w", err)
	}
	return channels, nil
}

// CreateAlertChannel creates a notification channel.
func (api *OsctrlAPI) CreateAlertChannel(name, typ, configJSON string, envID uint, enabled bool) error {
	body := struct {
		Name          string          `json:"name"`
		EnvironmentID uint            `json:"environment_id"`
		Type          string          `json:"type"`
		Enabled       bool            `json:"enabled"`
		Config        json.RawMessage `json:"config"`
	}{
		Name: name, EnvironmentID: envID, Type: typ, Enabled: enabled,
		Config: json.RawMessage(configJSON),
	}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "channels"))
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// DeleteAlertChannel removes a channel by ID.
func (api *OsctrlAPI) DeleteAlertChannel(id uint) error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "channels", strconv.FormatUint(uint64(id), 10)))
	raw, err := api.ReqGeneric("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// ApplyAlerts queues the reload-alerts service command for osctrl-tls.
func (api *OsctrlAPI) ApplyAlerts() error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/alerts", "apply"))
	raw, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}
