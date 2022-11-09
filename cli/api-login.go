package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/types"
)

// PostLogin to login into API to retrieve a token
func (api *OsctrlAPI) PostLogin(env, username, password string) (types.ApiLoginResponse, error) {
	var res types.ApiLoginResponse
	l := types.ApiLoginRequest{
		Username: username,
		Password: password,
	}
	jsonMessage, err := json.Marshal(l)
	if err != nil {
		return res, fmt.Errorf("error marshaling data %s", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APILogin, env)
	rawRes, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return res, fmt.Errorf("error api request - %v - %s", err, string(rawRes))
	}
	if err := json.Unmarshal(rawRes, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %v", err)
	}
	return res, nil
}
