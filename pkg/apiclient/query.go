package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// GetQueries to retrieve queries from osctrl
func (api *OsctrlAPI) GetQueries(target, env string) ([]queries.DistributedQuery, error) {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, "list", target))
	return getAllPages[queries.DistributedQuery](api, reqURL)
}

// GetQueriesLimited is GetQueries bounded to maxItems (> 0): it stops fetching
// pages once the cap is exceeded and reports whether more queries exist.
func (api *OsctrlAPI) GetQueriesLimited(target, env string, maxItems int) ([]queries.DistributedQuery, bool, error) {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, "list", target))
	return getPages[queries.DistributedQuery](api, reqURL, maxItems)
}

// GetQuery to retrieve one query from osctrl
func (api *OsctrlAPI) GetQuery(env, name string) (queries.DistributedQuery, error) {
	var q queries.DistributedQuery
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, name))
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
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, settings.QueryDelete, name))
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
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, settings.QueryExpire, name))
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
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, settings.QueryComplete, name))
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
func (api *OsctrlAPI) RunQuery(env, query string, uuids, hosts, platforms, tags []string, hidden bool, exp int) (types.ApiQueriesResponse, error) {
	q := types.ApiDistributedQueryRequest{
		UUIDs:     uuids,
		Hosts:     hosts,
		Platforms: platforms,
		Tags:      tags,
		Query:     query,
		Hidden:    hidden,
		ExpHours:  exp,
	}
	var r types.ApiQueriesResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env))
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

// GetQueryResults to retrieve the results collected so far for a query.
//
// Distributed queries are asynchronous: RunQuery returns as soon as the query
// is scheduled, and rows arrive over the following seconds or minutes as nodes
// check in. Callers poll this until TotalItems stops growing — there is no
// "query finished" signal beyond the query's own expiration.
//
// page starts at 1; pageSize is clamped server-side to 1000 (default 100).
// Requires QueryLevel on the environment, not merely UserLevel.
func (api *OsctrlAPI) GetQueryResults(env, name string, page, pageSize int) (types.QueryResultsResponse, error) {
	var r types.QueryResultsResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, env, "results", name))
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("page_size", strconv.Itoa(pageSize))
	}
	if len(q) > 0 {
		reqURL += "?" + q.Encode()
	}
	rawR, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("error api request - %w - %s", err, string(rawR))
	}
	if err := json.Unmarshal(rawR, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}
