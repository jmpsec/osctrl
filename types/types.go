package types

// JSONConfigurationTLS to hold TLS service configuration values
type JSONConfigurationTLS struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
	Logger   string `json:"logger"`
	Carver   string `json:"carver"`
}

// JSONConfigurationAdmin to hold admin service configuration values
type JSONConfigurationAdmin struct {
	Listener   string `json:"listener"`
	Port       string `json:"port"`
	Host       string `json:"host"`
	Auth       string `json:"auth"`
	Logger     string `json:"logger"`
	Carver     string `json:"carver"`
	SessionKey string `json:"sessionKey"`
}

// JSONConfigurationAPI to hold API service configuration values
type JSONConfigurationAPI struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
	Carver   string `json:"carver"`
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
	DefaultEnv        string `json:"defaultEnv"`
}

// JSONConfigurationJWT to hold all JWT configuration values
type JSONConfigurationJWT struct {
	JWTSecret     string `json:"jwtSecret"`
	HoursToExpire int    `json:"hoursToExpire"`
}

// OsqueryTable to show tables to query
type OsqueryTable struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Platforms []string `json:"platforms"`
	Filter    string
}

// FlagsRequest to retrieve flags
type FlagsRequest struct {
	Secret      string `json:"secret"`
	SecrefFile  string `json:"secretFile"`
	Certificate string `json:"certificate"`
}

// ScriptRequest to retrieve script
type ScriptRequest struct {
	Secret      string `json:"secret"`
	SecrefFile  string `json:"secretFile"`
	FlagsFile   string `json:"flagsFile"`
	Certificate string `json:"certificate"`
}
