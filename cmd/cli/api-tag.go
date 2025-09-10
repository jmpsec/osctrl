package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
)

// GetAllTags to retrieve all tags from osctrl
func (api *OsctrlAPI) GetAllTags() ([]tags.AdminTag, error) {
	var tgs []tags.AdminTag
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags))
	rawTgs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return tgs, fmt.Errorf("error api request - %w - %s", err, string(rawTgs))
	}
	if err := json.Unmarshal(rawTgs, &tgs); err != nil {
		return tgs, fmt.Errorf("can not parse body - %w", err)
	}
	return tgs, nil
}

// GetTags to retrieve tags from osctrl by environment
func (api *OsctrlAPI) GetTags(env string) ([]tags.AdminTag, error) {
	var tgs []tags.AdminTag
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags, env))
	rawTgs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return tgs, fmt.Errorf("error api request - %w - %s", err, string(rawTgs))
	}
	if err := json.Unmarshal(rawTgs, &tgs); err != nil {
		return tgs, fmt.Errorf("can not parse body - %w", err)
	}
	return tgs, nil
}

// GetTag to retrieve a tag from osctrl by environment and name
func (api *OsctrlAPI) GetTag(env, name string) (tags.AdminTag, error) {
	var t tags.AdminTag
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags, env, name))
	rawT, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return t, fmt.Errorf("error api request - %w - %s", err, string(rawT))
	}
	if err := json.Unmarshal(rawT, &t); err != nil {
		return t, fmt.Errorf("can not parse body - %w", err)
	}
	return t, nil
}

// AddTag to add a tag to osctrl
func (api *OsctrlAPI) AddTag(env, name, color, icon, description string, tagType uint, custom string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name:        name,
		Description: description,
		Color:       color,
		Icon:        icon,
		Env:         env,
		TagType:     tagType,
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags, env, tags.ActionAdd))
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %w", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}

// DeleteTag to delete a tag from osctrl
func (api *OsctrlAPI) DeleteTag(env, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name: name,
		Env:  env,
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags, env, tags.ActionRemove))
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %w", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}

// EditTag to edit a tag from osctrl
func (api *OsctrlAPI) EditTag(env, name, color, icon, description string, tagType uint) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name:        name,
		Description: description,
		Color:       color,
		Icon:        icon,
		Env:         env,
		TagType:     tagType,
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APITags, env, tags.ActionEdit))
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %w", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %w", err)
	}
	return r, nil
}
