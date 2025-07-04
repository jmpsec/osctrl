package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
)

// GetNodes to retrieve nodes from osctrl
func (api *OsctrlAPI) GetNodes(env, target string) ([]nodes.OsqueryNode, error) {
	var nds []nodes.OsqueryNode
	reqURL := path.Join(api.Configuration.URL, APIPath, APINodes, env, target)
	rawNodes, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return nds, fmt.Errorf("error api request - %w - %s", err, string(rawNodes))
	}
	if err := json.Unmarshal(rawNodes, &nds); err != nil {
		return nds, fmt.Errorf("can not parse body - %w", err)
	}
	return nds, nil
}

// GetNode to retrieve one node from osctrl
func (api *OsctrlAPI) GetNode(env, identifier string) (nodes.OsqueryNode, error) {
	var node nodes.OsqueryNode
	reqURL := path.Join(api.Configuration.URL, APIPath, APINodes, env, "node", identifier)
	rawNode, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return node, fmt.Errorf("error api request - %w - %s", err, string(rawNode))
	}
	if err := json.Unmarshal(rawNode, &node); err != nil {
		return node, fmt.Errorf("can not parse body - %w", err)
	}
	return node, nil
}

// DeleteNode to delete node from osctrl
func (api *OsctrlAPI) DeleteNode(env, identifier string) error {
	n := types.ApiNodeGenericRequest{
		UUID: identifier,
	}
	var r types.ApiGenericResponse
	reqURL := path.Join(api.Configuration.URL, APIPath, APINodes, env, "delete")
	jsonMessage, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawN, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(rawN))
	}
	if err := json.Unmarshal(rawN, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// TagNode to tag node in osctrl
func (api *OsctrlAPI) TagNode(env, identifier, tag string) error {
	return nil
}

// LookupNode to look up node from osctrl by identifier (UUID, localname or hostname)
func (api *OsctrlAPI) LookupNode(identifier string) (nodes.OsqueryNode, error) {
	var node nodes.OsqueryNode
	l := types.ApiLookupRequest{
		Identifier: identifier,
	}
	jsonMessage, err := json.Marshal(l)
	if err != nil {
		return node, fmt.Errorf("error marshaling data %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	reqURL := path.Join(api.Configuration.URL, APIPath, APINodes, "lookup")
	rawNode, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return node, fmt.Errorf("error api request - %w - %s", err, string(rawNode))
	}
	if err := json.Unmarshal(rawNode, &node); err != nil {
		return node, fmt.Errorf("can not parse body - %w", err)
	}
	return node, nil
}
