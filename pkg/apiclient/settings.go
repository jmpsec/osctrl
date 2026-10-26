package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// GetSettings retrieves all settings from osctrl
func (api *OsctrlAPI) GetSettings() ([]settings.SettingValue, error) {
	var vals []settings.SettingValue
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APISettings))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return vals, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &vals); err != nil {
		return vals, fmt.Errorf("can not parse body - %w", err)
	}
	return vals, nil
}

// PatchSetting updates an existing global setting
func (api *OsctrlAPI) PatchSetting(service, name string, req types.SettingPatchRequest) error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APISettings, service, name))
	jsonMessage, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	if raw, err := api.ReqGeneric(http.MethodPatch, reqURL, bytes.NewReader(jsonMessage)); err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}
