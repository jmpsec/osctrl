package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

// GetEnvironments to retrieve all environments from osctrl
func (api *OsctrlAPI) GetEnvironments() ([]environments.TLSEnvironment, error) {
	var envs []environments.TLSEnvironment
	reqURL := fmt.Sprintf("%s%s%s", api.Configuration.URL, APIPath, APIEnvironments)
	rawEnvs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return envs, fmt.Errorf("error api request - %v - %s", err, string(rawEnvs))
	}
	if err := json.Unmarshal(rawEnvs, &envs); err != nil {
		return envs, fmt.Errorf("can not parse body - %v", err)
	}
	return envs, nil
}

// GetEnvironment to retrieve users from osctrl
func (api *OsctrlAPI) GetEnvironment(identifier string) (environments.TLSEnvironment, error) {
	var e environments.TLSEnvironment
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APIEnvironments, identifier)
	rawE, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return e, fmt.Errorf("error api request - %v - %s", err, string(rawE))
	}
	if err := json.Unmarshal(rawE, &e); err != nil {
		return e, fmt.Errorf("can not parse body - %v", err)
	}
	return e, nil
}

// GetEnvMap to retrieve a map of environments by ID
func (api *OsctrlAPI) GetEnvMap() (environments.MapEnvByID, error) {
	var envMap environments.MapEnvByID
	reqURL := fmt.Sprintf("%s%s%s/map/id", api.Configuration.URL, APIPath, APIEnvironments)
	rawE, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return envMap, fmt.Errorf("error api request - %v - %s", err, string(rawE))
	}
	if err := json.Unmarshal(rawE, &envMap); err != nil {
		return envMap, fmt.Errorf("can not parse body - %v", err)
	}
	return envMap, nil
}

// ExtendEnrollment to extend in time the enrollment URL of an environment
func (api *OsctrlAPI) ExtendEnrollment(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionExtend, "enroll", nil)
}

// RotateEnrollment to rotate the enrollment URL of an environment
func (api *OsctrlAPI) RotateEnrollment(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionRotate, "enroll", nil)
}

// ExpireEnrollment to expire the enrollment URL of an environment
func (api *OsctrlAPI) ExpireEnrollment(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionExpire, "enroll", nil)
}

// NotexpireEnrollment to disable expiration for the enrollment URL of an environment
func (api *OsctrlAPI) NotexpireEnrollment(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionNotexpire, "enroll", nil)
}

// ExtendRemove to extend in time the remove URL of an environment
func (api *OsctrlAPI) ExtendRemove(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionExtend, "remove", nil)
}

// RotateEnrollment to rotate the remove URL of an environment
func (api *OsctrlAPI) RotateRemove(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionRotate, "remove", nil)
}

// ExpireRemove to expire the remove URL of an environment
func (api *OsctrlAPI) ExpireRemove(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionExpire, "remove", nil)
}

// NotexpireRemove to disable expiration for the remove URL of an environment
func (api *OsctrlAPI) NotexpireRemove(identifier string) (string, error) {
	return api.ActionEnrollmentRemove(identifier, settings.ActionNotexpire, "remove", nil)
}

// ExtendEnrollment to extend in time the enrollment URL of an environment
func (api *OsctrlAPI) ActionEnrollmentRemove(identifier, action, target string, data io.Reader) (string, error) {
	var res types.ApiGenericResponse
	reqURL := fmt.Sprintf("%s%s%s/%s/%s/%s", api.Configuration.URL, APIPath, APIEnvironments, identifier, target, action)
	rawE, err := api.PostGeneric(reqURL, data)
	if err != nil {
		return "", fmt.Errorf("error api request - %v - %s", err, string(rawE))
	}
	if err := json.Unmarshal(rawE, &res); err != nil {
		return "", fmt.Errorf("can not parse body - %v", err)
	}
	return res.Message, nil
}
