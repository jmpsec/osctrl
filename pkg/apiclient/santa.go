package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/santa"
)

// santa.go — REST wrappers for the Santa rule API.
//
// Routes:
//   GET    /api/v1/santa/{env}/rules
//   POST   /api/v1/santa/{env}/rules
//   DELETE /api/v1/santa/{env}/rules/{id}
//   POST   /api/v1/santa/{env}/rules/import[?dry_run=true]
//   GET    /api/v1/santa/{env}/machines
//   GET    /api/v1/santa/{env}/machines/{machineid}/rules
//   GET    /api/v1/santa/{env}/events

func (api *OsctrlAPI) santaRulesURL(env string, elem ...string) string {
	return api.Configuration.URL + path.Join(append([]string{APIPath, "/santa", url.PathEscape(env), "rules"}, elem...)...)
}

// GetSantaRules lists the Santa rules of an environment.
func (api *OsctrlAPI) GetSantaRules(env string) ([]santa.Rule, error) {
	var rules []santa.Rule
	raw, err := api.GetGeneric(api.santaRulesURL(env), nil)
	if err != nil {
		return rules, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return rules, fmt.Errorf("can not parse body - %w", err)
	}
	return rules, nil
}

func (api *OsctrlAPI) santaURL(env string, elem ...string) string {
	return api.Configuration.URL + path.Join(append([]string{APIPath, "/santa", url.PathEscape(env)}, elem...)...)
}

// santaGet fetches a Santa route and decodes its JSON body into out.
func (api *OsctrlAPI) santaGet(reqURL string, out any) error {
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// SantaEvents is one page of Santa execution events.
type SantaEvents struct {
	Events []santa.Event `json:"events"`
	Total  int64         `json:"total"`
	Page   int           `json:"page"`
}

// SantaEffectiveRules is what a machine gets at its next sync.
type SantaEffectiveRules struct {
	Rules      []santa.Rule `json:"rules"`
	ClientMode string       `json:"client_mode"`
	ModeSource string       `json:"mode_source"`
}

// GetSantaMachines lists the Santa machines of an environment.
func (api *OsctrlAPI) GetSantaMachines(env string) ([]santa.Machine, error) {
	var machines []santa.Machine
	return machines, api.santaGet(api.santaURL(env, "machines"), &machines)
}

// GetSantaEvents returns a newest-first page (1-based) of events matching f.
func (api *OsctrlAPI) GetSantaEvents(env string, f santa.EventFilter, page, pageSize int) (SantaEvents, error) {
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("page_size", strconv.Itoa(pageSize))
	for k, v := range map[string]string{"machine_id": f.MachineID, "decision": f.Decision, "sha256": f.SHA256} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var res SantaEvents
	return res, api.santaGet(api.santaURL(env, "events")+"?"+q.Encode(), &res)
}

// GetSantaEffectiveRules returns the rules and client mode applying to one node.
func (api *OsctrlAPI) GetSantaEffectiveRules(env, machineID string) (SantaEffectiveRules, error) {
	var res SantaEffectiveRules
	return res, api.santaGet(api.santaURL(env, "machines", url.PathEscape(machineID), "rules"), &res)
}

// CreateSantaRule creates one rule and returns it as stored.
func (api *OsctrlAPI) CreateSantaRule(env string, spec santa.RuleSpec) (santa.Rule, error) {
	var rule santa.Rule
	body, err := json.Marshal(spec)
	if err != nil {
		return rule, fmt.Errorf("error marshaling data - %w", err)
	}
	raw, err := api.PostGeneric(api.santaRulesURL(env), bytes.NewReader(body))
	if err != nil {
		return rule, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &rule); err != nil {
		return rule, fmt.Errorf("can not parse body - %w", err)
	}
	return rule, nil
}

// DeleteSantaRule deletes one rule by id.
func (api *OsctrlAPI) DeleteSantaRule(env string, id uint) error {
	raw, err := api.ReqGeneric(http.MethodDelete, api.santaRulesURL(env, strconv.FormatUint(uint64(id), 10)), nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// ImportSantaRules imports rules into an environment; with dryRun nothing is stored.
func (api *OsctrlAPI) ImportSantaRules(env string, specs []santa.RuleSpec, dryRun bool) (santa.ImportResult, error) {
	var res santa.ImportResult
	body, err := json.Marshal(specs)
	if err != nil {
		return res, fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := api.santaRulesURL(env, "import")
	if dryRun {
		reqURL += "?dry_run=true"
	}
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(body))
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}
