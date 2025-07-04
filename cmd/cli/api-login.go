package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/types"
)

// PostLogin to login into API to retrieve a token
func (api *OsctrlAPI) PostLogin(env, username, password string, expHours int) (types.ApiLoginResponse, error) {
	var res types.ApiLoginResponse
	l := types.ApiLoginRequest{
		Username: username,
		Password: password,
		ExpHours: expHours,
	}
	jsonMessage, err := json.Marshal(l)
	if err != nil {
		return res, fmt.Errorf("error marshaling data %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	reqURL := path.Join(api.Configuration.URL, APIPath, APILogin, env)
	rawRes, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(rawRes))
	}
	if err := json.Unmarshal(rawRes, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}
