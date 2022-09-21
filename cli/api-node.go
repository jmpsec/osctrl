package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/nodes"
)

// GetNodes to retrieve nodes from osctrl
func (api *OsctrlAPI) GetNodes(env string) ([]nodes.OsqueryNode, error) {
	var nds []nodes.OsqueryNode
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APINodes, env)
	rawNodes, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return nds, fmt.Errorf("error api request - %v", err)
	}
	if err := json.Unmarshal(rawNodes, &nds); err != nil {
		return nds, fmt.Errorf("can not parse body - %v", err)
	}
	return nds, nil
}

// GetNode to retrieve one node from osctrl
func (api *OsctrlAPI) GetNode(env, identifier string) (nodes.OsqueryNode, error) {
	var node nodes.OsqueryNode
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APINodes, env, identifier)
	rawNode, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return node, fmt.Errorf("error api request - %v", err)
	}
	if err := json.Unmarshal(rawNode, &node); err != nil {
		return node, fmt.Errorf("can not parse body - %v", err)
	}
	return node, nil
}

// DeleteNode to delete node from osctrl
func (api *OsctrlAPI) DeleteNode(identifier string) error {
	return nil
}
