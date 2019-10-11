package types

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	MaxOpenConns    int    `json:"max_open_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
}

// JSONConfigurationService to hold all service configuration values
type JSONConfigurationService struct {
	Listener string `json:"listener"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Auth     string `json:"auth"`
	Logging  string `json:"logging"`
}

// JSONConfigurationHeaders to keep all SAML details for auth
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
