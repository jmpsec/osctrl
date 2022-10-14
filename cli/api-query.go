package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/types"
)

// GetQueries to retrieve queries from osctrl
func (api *OsctrlAPI) GetQueries(env string) ([]queries.DistributedQuery, error) {
	var qs []queries.DistributedQuery
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APIQueries, env)
	rawQs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return qs, fmt.Errorf("error api request - %v - %s", err, string(rawQs))
	}
	if err := json.Unmarshal(rawQs, &qs); err != nil {
		return qs, fmt.Errorf("can not parse body - %v", err)
	}
	return qs, nil
}

// GetQuery to retrieve one query from osctrl
func (api *OsctrlAPI) GetQuery(env, name string) (queries.DistributedQuery, error) {
	var q queries.DistributedQuery
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APIQueries, env, name)
	rawQ, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return q, fmt.Errorf("error api request - %v - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &q); err != nil {
		return q, fmt.Errorf("can not parse body - %v", err)
	}
	return q, nil
}

// DeleteQuery to delete query from osctrl
func (api *OsctrlAPI) DeleteQuery(env, identifier string) error {
	return nil
}

// CompleteQuery to complete a query from osctrl
func (api *OsctrlAPI) CompleteQuery(env, identifier string) error {
	return nil
}

// RunQuery to initiate a query in osctrl
func (api *OsctrlAPI) RunQuery(env, uuid, query string, hidden bool) (types.ApiQueriesResponse, error) {
	q := types.ApiDistributedQueryRequest{
		UUID:   uuid,
		Query:  query,
		Hidden: hidden,
	}
	var r types.ApiQueriesResponse
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APIQueries, env)
	jsonMessage, err := json.Marshal(q)
	if err != nil {
		log.Printf("error marshaling data %s", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawQ, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %v - %s", err, string(rawQ))
	}
	if err := json.Unmarshal(rawQ, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}
