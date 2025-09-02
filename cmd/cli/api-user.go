package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
)

// GetUsers to retrieve users from osctrl
func (api *OsctrlAPI) GetUsers() ([]users.AdminUser, error) {
	var us []users.AdminUser
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers))
	rawUs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return us, fmt.Errorf("error api request - %w - %s", err, string(rawUs))
	}
	if err := json.Unmarshal(rawUs, &us); err != nil {
		return us, fmt.Errorf("can not parse body - %w", err)
	}
	return us, nil
}

// GetUser to retrieve one user from osctrl
func (api *OsctrlAPI) GetUser(username string) (users.AdminUser, error) {
	var u users.AdminUser
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, username))
	rawU, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return u, fmt.Errorf("error api request - %w - %s", err, string(rawU))
	}
	if err := json.Unmarshal(rawU, &u); err != nil {
		return u, fmt.Errorf("can not parse body - %w", err)
	}
	return u, nil
}

// DeleteUser to delete user from osctrl
func (api *OsctrlAPI) DeleteUser(username string) error {
	u := types.ApiUserRequest{
		Username: username,
	}
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, username, users.ActionRemove))
	jsonMessage, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawU, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(rawU))
	}
	if err := json.Unmarshal(rawU, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// CreateUser to create user in osctrl, it also creates permissions
func (api *OsctrlAPI) CreateUser(username, password, email, fullname, environment string, admin, service bool) error {
	u := types.ApiUserRequest{
		Username:     username,
		Password:     password,
		Email:        email,
		Fullname:     fullname,
		Admin:        admin,
		Service:      service,
		Environments: []string{environment},
	}
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, username, users.ActionAdd))
	jsonMessage, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawU, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(rawU))
	}
	if err := json.Unmarshal(rawU, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// EditUserReq to edit a user in osctrl, it takes a ApiUserRequest as input
func (api *OsctrlAPI) EditUserReq(u types.ApiUserRequest) error {
	var r types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIUSers, u.Username, users.ActionEdit))
	jsonMessage, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	jsonParam := bytes.NewReader(jsonMessage)
	rawU, err := api.PostGeneric(reqURL, jsonParam)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(rawU))
	}
	if err := json.Unmarshal(rawU, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// EditUser to edit a user in osctrl, it takes individual parameters as input
func (api *OsctrlAPI) EditUser(username, password, email, fullname, environment string, admin, service bool) error {
	u := types.ApiUserRequest{
		Username:     username,
		Password:     password,
		Email:        email,
		Fullname:     fullname,
		Admin:        admin,
		Service:      service,
		Environments: []string{environment},
	}
	return api.EditUserReq(u)
}
