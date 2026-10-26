package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/jmpsec/osctrl/pkg/types"
)

// envConfigURL is GET/PATCH /api/v1/environments/config/{env}.
func (api *OsctrlAPI) envConfigURL(env string) string {
	return fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIEnvironments, "config", url.PathEscape(env)))
}

// GetEnvConfig retrieves the raw configuration sections of an environment
func (api *OsctrlAPI) GetEnvConfig(env string) (types.EnvConfigResponse, error) {
	var cnf types.EnvConfigResponse
	raw, err := api.GetGeneric(api.envConfigURL(env), nil)
	if err != nil {
		return cnf, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &cnf); err != nil {
		return cnf, fmt.Errorf("can not parse body - %w", err)
	}
	return cnf, nil
}

// PatchEnvConfig replaces one whole configuration section (options, schedule,
// packs, decorators, atc or flags) of an environment with value
func (api *OsctrlAPI) PatchEnvConfig(env, section, value string) error {
	var req types.EnvConfigPatchRequest
	field := map[string]**string{
		"options": &req.Options, "schedule": &req.Schedule, "packs": &req.Packs,
		"decorators": &req.Decorators, "atc": &req.ATC, "flags": &req.Flags,
	}[section]
	if field == nil {
		return fmt.Errorf("unknown configuration section %q", section)
	}
	*field = &value
	jsonMessage, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	if raw, err := api.ReqGeneric(http.MethodPatch, api.envConfigURL(env), bytes.NewReader(jsonMessage)); err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}
