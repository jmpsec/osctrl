package types

// JSONConfigurationService to hold all service configuration values
type JSONConfigurationService struct {
	Listener    string `json:"listener"`
	Port        string `json:"port"`
	Host        string `json:"host"`
	Auth        string `json:"auth"`
	Logging     string `json:"logging"`
}

// JSONConfigurationHeaders to keep all headers details for auth
type JSONConfigurationHeaders struct {
	TrustedPrefix     string `json:"trustedPrefix"`
	AdminGroup        string `json:"adminGroup"`
	UserGroup         string `json:"userGroup"`
	Email             string `json:"email"`
	UserName          string `json:"userName"`
	FirstName         string `json:"firstName"`
	LastName          string `json:"lastName"`
	DisplayName       string `json:"displayName"`
	DistinguishedName string `json:"distinguishedName"`
	Groups            string `json:"groups"`
}

// JSONConfigurationJWT to hold all JWT configuration values
type JSONConfigurationJWT struct {
	JWTSecret     string `json:"jwtSecret"`
	HoursToExpire int    `json:"hoursToExpire"`
}
