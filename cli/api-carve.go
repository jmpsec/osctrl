package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/rs/zerolog/log"
)

// GetCarveQueries to retrieve carves from osctrl
func (api *OsctrlAPI) GetCarveQueries(target, env string) ([]queries.DistributedQuery, error) {
	var qs []queries.DistributedQuery
	reqURL := fmt.Sprintf("%s%s%s/%s/queries/%s", api.Configuration.URL, APIPath, APICarves, env, target)
	rawCs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return qs, fmt.Errorf("error api request - %v - %s", err, string(rawCs))
	}
	if err := json.Unmarshal(rawCs, &qs); err != nil {
		return qs, fmt.Errorf("can not parse body - %v", err)
	}
	return qs, nil
}

// GetCarves to retrieve carves from osctrl
func (api *OsctrlAPI) GetCarves(env string) ([]carves.CarvedFile, error) {
	var cs []carves.CarvedFile
	reqURL := fmt.Sprintf("%s%s%s/%s/list", api.Configuration.URL, APIPath, APICarves, env)
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
func (api *OsctrlAPI) DeleteCarve(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s%s/%s/%s/%s", api.Configuration.URL, APIPath, APICarves, env, settings.CarveDelete, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %v - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}

// ExpireCarve to expire carve from osctrl
func (api *OsctrlAPI) ExpireCarve(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s%s/%s/%s/%s", api.Configuration.URL, APIPath, APICarves, env, settings.QueryExpire, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %v - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}

// CompleteCarve to complete a carve from osctrl
func (api *OsctrlAPI) CompleteCarve(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s%s/%s/%s/%s", api.Configuration.URL, APIPath, APICarves, env, settings.CarveComplete, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %v - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}

// RunCarve to initiate a carve in osctrl
func (api *OsctrlAPI) RunCarve(env, uuid, path string, exp int) (types.ApiQueriesResponse, error) {
	c := types.ApiDistributedCarveRequest{
		UUID:     uuid,
		Path:     path,
		ExpHours: exp,
	}
	var r types.ApiQueriesResponse
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APICarves, env)
	jsonMessage, err := json.Marshal(c)
	if err != nil {
		log.Err(err).Msg("error marshaling data")
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawC, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %v - %s", err, string(rawC))
	}
	if err := json.Unmarshal(rawC, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}
