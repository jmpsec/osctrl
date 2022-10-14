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

// S3Configuration to hold all S3 configuration values
type S3Configuration struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKey       string `json:"accessKey"`
	SecretAccessKey string `json:"secretAccesKey"`
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
	Secret     string `json:"secret"`
	SecrefFile string `json:"secretFile"`
	CertFile   string `json:"certFile"`
}

// CertRequest to retrieve certificate
type CertRequest FlagsRequest

// VerifyRequest to verify nodes
type VerifyRequest FlagsRequest

// VerifyResponse for verify requests from osctrld
type VerifyResponse struct {
	Flags          string `json:"flags"`
	Certificate    string `json:"certificate"`
	OsqueryVersion string `json:"osquery_version"`
}

// ScriptRequest to retrieve script
type ScriptRequest struct {
	Secret      string `json:"secret"`
	SecrefFile  string `json:"secretFile"`
	FlagsFile   string `json:"flagsFile"`
	Certificate string `json:"certificate"`
}

// ApiDistributedQueryRequest to receive query requests
type ApiDistributedQueryRequest struct {
	UUID   string `json:"uuid"`
	Query  string `json:"query"`
	Hidden bool   `json:"hidden"`
}

// ApiDistributedCarveRequest to receive query requests
type ApiDistributedCarveRequest struct {
	UUID string `json:"uuid"`
	Path string `json:"path"`
}

// ApiErrorResponse to be returned to API requests with the error message
type ApiErrorResponse struct {
	Error string `json:"error"`
}

// ApiQueriesResponse to be returned to API requests for queries
type ApiQueriesResponse struct {
	Name string `json:"query_name"`
}
