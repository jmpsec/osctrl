package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/carves"
)

// GetCarves to retrieve carves from osctrl
func (api *OsctrlAPI) GetCarves(env string) ([]carves.CarvedFile, error) {
	var cs []carves.CarvedFile
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APICarves, env)
	rawCs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return cs, fmt.Errorf("error api request - %v - %s", err, string(rawCs))
	}
	if err := json.Unmarshal(rawCs, &cs); err != nil {
		return cs, fmt.Errorf("can not parse body - %v", err)
	}
	return cs, nil
}

// GetCarve to retrieve one carve from osctrl
func (api *OsctrlAPI) GetCarve(env, name string) (carves.CarvedFile, error) {
	var c carves.CarvedFile
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APICarves, env, name)
	rawC, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return c, fmt.Errorf("error api request - %v - %s", err, string(rawC))
	}
	if err := json.Unmarshal(rawC, &c); err != nil {
		return c, fmt.Errorf("can not parse body - %v", err)
	}
	return c, nil
}

// DeleteCarve to delete carve from osctrl
func (api *OsctrlAPI) DeleteCarve(env, identifier string) error {
	return nil
}

// CompleteCarve to complete a carve from osctrl
func (api *OsctrlAPI) CompleteCarve(env, identifier string) error {
	return nil
}
