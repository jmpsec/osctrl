package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"

	"github.com/jmpsec/osctrl/pkg/santa"
)

// santa.go — REST wrappers for the Santa rule API.
//
// Routes:
//   GET  /api/v1/santa/{env}/rules
//   POST /api/v1/santa/{env}/rules/import[?dry_run=true]

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
