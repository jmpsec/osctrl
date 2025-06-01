package types

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
	UUIDs        []string `json:"uuid_list"`
	Platforms    []string `json:"platform_list"`
	Environments []string `json:"environment_list"`
	Hosts        []string `json:"host_list"`
	Query        string   `json:"query"`
	Hidden       bool     `json:"hidden"`
	ExpHours     int      `json:"exp_hours"`
}

// ApiDistributedCarveRequest to receive query requests
type ApiDistributedCarveRequest struct {
	UUID     string `json:"uuid"`
	Path     string `json:"path"`
	ExpHours int    `json:"exp_hours"`
}

// ApiNodeGenericRequest to receive generic node requests
type ApiNodeGenericRequest struct {
	UUID string `json:"uuid"`
}

// ApiLoginRequest to receive login requests
type ApiLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ExpHours int    `json:"exp_hours"`
}

// ApiErrorResponse to be returned to API requests with the error message
type ApiErrorResponse struct {
	Error string `json:"error"`
}

// ApiQueriesResponse to be returned to API requests for queries
type ApiQueriesResponse struct {
	Name string `json:"query_name"`
}

// ApiGenericResponse to be returned to API requests for anything
type ApiGenericResponse struct {
	Message string `json:"message"`
}

// ApiDataResponse to be returned to API requests for generic data
type ApiDataResponse struct {
	Data string `json:"data"`
}

// ApiLoginResponse to be returned to API login requests with the generated token
type ApiLoginResponse struct {
	Token string `json:"token"`
}

// ApiActionsRequest to receive action requests
type ApiActionsRequest struct {
	Certificate string `json:"certificate"`
	MacPkgURL   string `json:"url_mac_pkg"`
	MsiPkgURL   string `json:"url_msi_pkg"`
	RpmPkgURL   string `json:"url_rpm_pkg"`
	DebPkgURL   string `json:"url_deb_pkg"`
}

// ApiTagsRequest to receive tag requests
type ApiTagsRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Icon        string `json:"icon"`
	EnvUUID     string `json:"env_uuid"`
	TagType     uint   `json:"tagtype"`
}

// ApiLookupRequest to receive lookup requests
type ApiLookupRequest struct {
	Identifier string `json:"identifier"`
}
