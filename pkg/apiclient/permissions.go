package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
)

// GetUserPermissions returns the per-environment access of a user, keyed by
// environment UUID. Environments without permission rows are absent.
func (api *OsctrlAPI) GetUserPermissions(username string) (types.GetPermissionsResponse, error) {
	var resp types.GetPermissionsResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, url.PathEscape(username), "permissions"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return resp, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, fmt.Errorf("can not parse body - %w", err)
	}
	return resp, nil
}

// SetUserPermissions replaces all four access levels of a user on an
// environment (identified by UUID).
func (api *OsctrlAPI) SetUserPermissions(username, envUUID string, access users.EnvAccess) error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, url.PathEscape(username), "permissions"))
	// types.EnvAccessView omits an empty scope_tags, but the server reads
	// "[]" as clear and an absent key as unchanged, so send it as a pointer.
	body := struct {
		EnvUUID string `json:"env_uuid"`
		Access  struct {
			types.EnvAccessView
			ScopeTags *[]uint `json:"scope_tags,omitempty"`
		} `json:"access"`
	}{EnvUUID: envUUID}
	body.Access.EnvAccessView = types.EnvAccessView{User: access.User, Query: access.Query, Carve: access.Carve, Admin: access.Admin, QueryTier: access.QueryTier, CarveTier: access.CarveTier}
	if access.ScopeTags != nil {
		body.Access.ScopeTags = &access.ScopeTags
	}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	if raw, err := api.ReqGeneric(http.MethodPost, reqURL, bytes.NewReader(jsonMessage)); err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}
