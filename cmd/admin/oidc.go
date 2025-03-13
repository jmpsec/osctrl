package main

// JSONConfigurationOIDC to keep all OIDC details for auth
type JSONConfigurationOIDC struct {
	IssuerURL         string   `json:"issuerurl"`
	ClientID          string   `json:"clientid"`
	ClientSecret      string   `json:"clientsecret"`
	RedirectURL       string   `json:"redirecturl"`
	Scope             []string `json:"scope"`
	Nonce             string   `json:"nonce"`
	ResponseType      string   `json:"responsetype"`
	AuthorizationCode string   `json:"authorizationcode"`
}
