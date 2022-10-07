package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/users"
)

// GetUsers to retrieve users from osctrl
func (api *OsctrlAPI) GetUsers() ([]users.AdminUser, error) {
	var us []users.AdminUser
	reqURL := fmt.Sprintf("%s%s%s", api.Configuration.URL, APIPath, APIUSers)
	rawUs, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return us, fmt.Errorf("error api request - %v - %s", err, string(rawUs))
	}
	if err := json.Unmarshal(rawUs, &us); err != nil {
		return us, fmt.Errorf("can not parse body - %v", err)
	}
	return us, nil
}

// GetUser to retrieve one user from osctrl
func (api *OsctrlAPI) GetUser(username string) (users.AdminUser, error) {
	var u users.AdminUser
	reqURL := fmt.Sprintf("%s%s%s/%s", api.Configuration.URL, APIPath, APIUSers, username)
	rawU, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return u, fmt.Errorf("error api request - %v - %s", err, string(rawU))
	}
	if err := json.Unmarshal(rawU, &u); err != nil {
		return u, fmt.Errorf("can not parse body - %v", err)
	}
	return u, nil
}

// DeleteUser to delete user from osctrl
func (api *OsctrlAPI) DeleteUser(username string) error {
	return nil
}
