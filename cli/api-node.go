package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/types"
)

// GetNodes to retrieve nodes from osctrl
func (api *OsctrlAPI) GetNodes(env, target string) ([]nodes.OsqueryNode, error) {
	var nds []nodes.OsqueryNode
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APINodes, env, target)
	rawNodes, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return nds, fmt.Errorf("error api request - %v - %s", err, string(rawNodes))
	}
	if err := json.Unmarshal(rawNodes, &nds); err != nil {
		return nds, fmt.Errorf("can not parse body - %v", err)
	}
	return nds, nil
}

// GetNode to retrieve one node from osctrl
func (api *OsctrlAPI) GetNode(env, identifier string) (nodes.OsqueryNode, error) {
	var node nodes.OsqueryNode
	reqURL := fmt.Sprintf("%s%s%s/%s/node/%s", api.Configuration.URL, APIPath, APINodes, env, identifier)
	rawNode, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return node, fmt.Errorf("error api request - %v - %s", err, string(rawNode))
	}
	if err := json.Unmarshal(rawNode, &node); err != nil {
		return node, fmt.Errorf("can not parse body - %v", err)
	}
	return node, nil
}

// DeleteNode to delete node from osctrl
func (api *OsctrlAPI) DeleteNode(env, identifier string) error {
	n := types.ApiNodeGenericRequest{
		UUID: identifier,
	}
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s%s/%s/delete", api.Configuration.URL, APIPath, APINodes, env)
	jsonMessage, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("error marshaling data - %v", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawN, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return fmt.Errorf("error api request - %v - %s", err, string(rawN))
	}
	if err := json.Unmarshal(rawN, &r); err != nil {
		return fmt.Errorf("can not parse body - %v", err)
	}
	return nil
}

// TagNode to tag node in osctrl
func (api *OsctrlAPI) TagNode(env, identifier, tag string) error {
	return nil
}
