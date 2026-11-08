package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
)

func (api *OsctrlAPI) sensitivePathsURL(env string, extra ...string) string {
	segs := append([]string{APIPath, APIEnvironments, "sensitive-paths", env}, extra...)
	return fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(segs...))
}

// ListSensitivePaths to retrieve the sensitive carve paths of an environment
func (api *OsctrlAPI) ListSensitivePaths(env string) ([]environments.SensitivePath, error) {
	var rows []environments.SensitivePath
	raw, err := api.GetGeneric(api.sensitivePathsURL(env), nil)
	if err != nil {
		return rows, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return rows, fmt.Errorf("can not parse body - %w", err)
	}
	return rows, nil
}

// AddSensitivePath to add a sensitive carve path to an environment
func (api *OsctrlAPI) AddSensitivePath(env, p string) (environments.SensitivePath, error) {
	var row environments.SensitivePath
	body, err := json.Marshal(types.ApiSensitivePathRequest{Path: p})
	if err != nil {
		return row, fmt.Errorf("error marshaling data - %w", err)
	}
	raw, err := api.PostGeneric(api.sensitivePathsURL(env), bytes.NewReader(body))
	if err != nil {
		return row, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return row, fmt.Errorf("can not parse body - %w", err)
	}
	return row, nil
}

// DeleteSensitivePath to remove a sensitive carve path from an environment
func (api *OsctrlAPI) DeleteSensitivePath(env string, id uint) error {
	raw, err := api.ReqGeneric(http.MethodDelete, api.sensitivePathsURL(env, strconv.FormatUint(uint64(id), 10)), nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}
