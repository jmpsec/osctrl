package main

import (
	"encoding/json"
	"fmt"
	"osctrl/internal/tags"
	"osctrl/internal/types"
	"strings"
)

// GetAllTags to retrieve all tags from osctrl
func (api *OsctrlAPI) GetAllTags() ([]tags.AdminTag, error) {
	var tgs []tags.AdminTag
	reqURL := fmt.Sprintf("%s%s%s", api.Configuration.URL, APIPath, APITags)
	rawTgs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return tgs, fmt.Errorf("error api request - %v - %s", err, string(rawTgs))
	}
	if err := json.Unmarshal(rawTgs, &tgs); err != nil {
		return tgs, fmt.Errorf("can not parse body - %v", err)
	}
	return tgs, nil
}

// GetTags to retrieve tags from osctrl by environment
func (api *OsctrlAPI) GetTags(env string) ([]tags.AdminTag, error) {
	var tgs []tags.AdminTag
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APITags, env)
	rawTgs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return tgs, fmt.Errorf("error api request - %v - %s", err, string(rawTgs))
	}
	if err := json.Unmarshal(rawTgs, &tgs); err != nil {
		return tgs, fmt.Errorf("can not parse body - %v", err)
	}
	return tgs, nil
}

// GetTag to retrieve a tag from osctrl by environment and name
func (api *OsctrlAPI) GetTag(env, name string) (tags.AdminTag, error) {
	var t tags.AdminTag
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APITags, env, name)
	rawT, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return t, fmt.Errorf("error api request - %v - %s", err, string(rawT))
	}
	if err := json.Unmarshal(rawT, &t); err != nil {
		return t, fmt.Errorf("can not parse body - %v", err)
	}
	return t, nil
}

// AddTag to add a tag to osctrl
func (api *OsctrlAPI) AddTag(envUUID, name, color, icon, description string, tagType uint) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name:        name,
		Description: description,
		Color:       color,
		Icon:        icon,
		EnvUUID:     envUUID,
		TagType:     tagType,
	}
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APITags, envUUID, tags.ActionAdd)
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %v", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %v", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}

// DeleteTag to delete a tag from osctrl
func (api *OsctrlAPI) DeleteTag(envUUID, name string) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name:    name,
		EnvUUID: envUUID,
	}
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APITags, envUUID, tags.ActionRemove)
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %v", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %v", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}

// EditTag to edit a tag from osctrl
func (api *OsctrlAPI) EditTag(envUUID, name, color, icon, description string, tagType uint) (types.ApiGenericResponse, error) {
	var r types.ApiGenericResponse
	t := types.ApiTagsRequest{
		Name:        name,
		Description: description,
		Color:       color,
		Icon:        icon,
		EnvUUID:     envUUID,
		TagType:     tagType,
	}
	reqURL := fmt.Sprintf("%s%s%s/%s/%s", api.Configuration.URL, APIPath, APITags, envUUID, tags.ActionEdit)
	jsonMessage, err := json.Marshal(t)
	if err != nil {
		return r, fmt.Errorf("error marshaling data - %v", err)
	}
	jsonParam := strings.NewReader(string(jsonMessage))
	rawT, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return r, fmt.Errorf("error api request - %v", err)
	}
	if err := json.Unmarshal(rawT, &r); err != nil {
		return r, fmt.Errorf("can not parse body - %v", err)
	}
	return r, nil
}
