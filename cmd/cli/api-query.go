package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// GetQueries to retrieve queries from osctrl
func (api *OsctrlAPI) GetQueries(target, env string) ([]queries.DistributedQuery, error) {
	var qs []queries.DistributedQuery
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env, "list", target)
	rawQs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return qs, fmt.Errorf("error api request - %w - %s", err, string(rawQs))
	}
	if err := json.Unmarshal(rawQs, &qs); err != nil {
		return qs, fmt.Errorf("can not parse body - %w", err)
	}
	return qs, nil
}

// GetQuery to retrieve one query from osctrl
func (api *OsctrlAPI) GetQuery(env, name string) (queries.DistributedQuery, error) {
	var q queries.DistributedQuery
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env, name)
	rawQ, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return q, fmt.Errorf("error api request - %w - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &q); err != nil {
		return q, fmt.Errorf("can not parse body - %w", err)
	}
	return q, nil
}

// DeleteQuery to delete query from osctrl
func (api *OsctrlAPI) DeleteQuery(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env, settings.QueryDelete, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %w - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}

// ExpireQuery to expire query from osctrl
func (api *OsctrlAPI) ExpireQuery(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env, settings.QueryExpire, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %w - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}

// CompleteQuery to complete a query from osctrl
func (api *OsctrlAPI) CompleteQuery(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env, settings.QueryComplete, name)
	rawQ, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %w - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}

// RunQuery to initiate a query in osctrl
func (api *OsctrlAPI) RunQuery(env, uuid, query string, hidden bool, exp int) (types.ApiQueriesResponse, error) {
	q := types.ApiDistributedQueryRequest{
		UUIDs:    []string{uuid},
		Query:    query,
		Hidden:   hidden,
		ExpHours: exp,
	}
	var r types.ApiQueriesResponse
	reqURL := path.Join(api.Configuration.URL, APIPath, APIQueries, env)
	jsonMessage, err := json.Marshal(q)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %w", err)

	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawQ, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %w - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}
