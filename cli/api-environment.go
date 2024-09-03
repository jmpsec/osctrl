package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/environments"
)

// GetEnvironments to retrieve all environments from osctrl
func (api *OsctrlAPI) GetEnvironments() ([]environments.TLSEnvironment, error) {
	var envs []environments.TLSEnvironment
	reqURL := fmt.Sprintf("%s%s%s", api.Configuration.URL, APIPath, APIEnvironments)
	rawEnvs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return envs, fmt.Errorf("error api request - %v - %s", err, string(rawEnvs))
	}
	if err := json.Unmarshal(rawEnvs, &envs); err != nil {
		return envs, fmt.Errorf("can not parse body - %v", err)
	}
	return envs, nil
}

// GetEnvironment to retrieve users from osctrl
func (api *OsctrlAPI) GetEnvironment(identifier string) (environments.TLSEnvironment, error) {
	var e environments.TLSEnvironment
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APIEnvironments, identifier)
	rawE, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return e, fmt.Errorf("error api request - %v - %s", err, string(rawE))
	}
	if err := json.Unmarshal(rawE, &e); err != nil {
		return e, fmt.Errorf("can not parse body - %v", err)
	}
	return e, nil
}
