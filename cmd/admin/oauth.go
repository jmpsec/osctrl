package main

// JSONConfigurationOAuth to keep all OAuth details for auth
type JSONConfigurationOAuth struct {
	ClientID     string   `json:"clientid"`
	ClientSecret string   `json:"clientsecret"`
	RedirectURL  string   `json:"redirecturl"`
	Scopes       []string `json:"scopes"`
	EndpointURL  string   `json:"endpointurl"`
}
