package types

import "time"

// OsqueryTable to show tables to query
type OsqueryTable struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Platforms []string `json:"platforms"`
	Filter    string
}

// BuildMetadata to show build metadata
type BuildMetadata struct {
	Version string
	Commit  string
	Date    string
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

// OsqueryConfigRequest to receive osquery configuration requests
type OsqueryConfigRequest struct {
	Configuration string `json:"configuration"`
	Integrity     string `json:"integrity"`
}

// ApiDistributedQueryRequest to receive query requests
type ApiDistributedQueryRequest struct {
	UUIDs        []string `json:"uuid_list"`
	Platforms    []string `json:"platform_list"`
	Environments []string `json:"environment_list"`
	Hosts        []string `json:"host_list"`
	Tags         []string `json:"tag_list"`
	Query        string   `json:"query"`
	Path         string   `json:"path"`
	Hidden       bool     `json:"hidden"`
	ExpHours     int      `json:"exp_hours"`
}

// ApiNodeGenericRequest to receive generic node requests
type ApiNodeGenericRequest struct {
	UUID string `json:"uuid"`
}

// ApiNodeTagRequest to receive tag node requests
type ApiNodeTagRequest struct {
	UUID   string `json:"uuid"`
	Tag    string `json:"tag"`
	Type   uint   `json:"type"`
	Custom string `json:"custom"`
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
	Code  string `json:"code,omitempty"`
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
	Token     string `json:"token"`
	CSRFToken string `json:"csrf_token,omitempty"`
}

// ApiActionsRequest to receive action requests
type ApiActionsRequest struct {
	Certificate string `json:"certificate"`
	MacPkgURL   string `json:"url_mac_pkg"`
	MsiPkgURL   string `json:"url_msi_pkg"`
	RpmPkgURL   string `json:"url_rpm_pkg"`
	DebPkgURL   string `json:"url_deb_pkg"`
}

// ApiEnvRequest to receive environment action requests
type ApiEnvRequest struct {
	Action   string `json:"action"`
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Icon     string `json:"icon"`
	Type     string `json:"type"`
}

// ApiTagsRequest to receive tag requests
type ApiTagsRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Icon        string `json:"icon"`
	Env         string `json:"env"`
	TagType     uint   `json:"tagtype"`
	Custom      string `json:"custom"`
}

// ApiLookupRequest to receive lookup requests
type ApiLookupRequest struct {
	Identifier string `json:"identifier"`
}

// ApiUserRequest to receive user requests
type ApiUserRequest struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	Email        string   `json:"email"`
	Fullname     string   `json:"fullname"`
	Admin        bool     `json:"admin"`
	NotAdmin     bool     `json:"not_admin"`
	Service      bool     `json:"service"`
	NotService   bool     `json:"not_service"`
	API          bool     `json:"api"`
	Environments []string `json:"environments"`
}

// TLSEnvironmentView is the low-privilege projection of an environment.
// UserLevel operators (env scope) need basic env metadata so the SPA can
// render its env switcher / dashboard / table chrome — but they MUST NOT
// receive the enroll secret, the certificate, or one-liner URLs that
// embed the secret. The full storage struct is admin-only via
// EnvironmentAdminHandler.
type TLSEnvironmentView struct {
	ID             uint      `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	UUID           string    `json:"uuid"`
	Name           string    `json:"name"`
	Hostname       string    `json:"hostname"`
	Type           string    `json:"type"`
	Icon           string    `json:"icon"`
	DebugHTTP      bool      `json:"debug_http"`
	ConfigTLS      bool      `json:"config_tls"`
	ConfigInterval int       `json:"config_interval"`
	LoggingTLS     bool      `json:"logging_tls"`
	LogInterval    int       `json:"log_interval"`
	QueryTLS       bool      `json:"query_tls"`
	QueryInterval  int       `json:"query_interval"`
	CarvesTLS      bool      `json:"carves_tls"`
	AcceptEnrolls  bool      `json:"accept_enrolls"`
	EnrollExpire   time.Time `json:"enroll_expire"`
	RemoveExpire   time.Time `json:"remove_expire"`
}

// AdminUserView is the PII-minimized projection of an AdminUser for
// the GET /api/v1/users and GET /api/v1/users/{username} endpoints.
// Drops LastIPAddress / LastUserAgent / LastAccess / LastTokenUse: a
// super-admin reading another super-admin's record gets enough to
// manage them (username, email, fullname, admin/service flags, env
// scope) but not the network/timing metadata that helps an attacker
// who later compromises one super-admin profile target the others.
//
// Users querying THEIR OWN record see the metadata they need via the
// pre-existing UserMeResponse from /api/v1/users/me — this view is
// strictly for the cross-user "list / inspect another admin" paths.
type AdminUserView struct {
	ID            uint      `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	Fullname      string    `json:"fullname"`
	Admin         bool      `json:"admin"`
	Service       bool      `json:"service"`
	UUID          string    `json:"uuid"`
	TokenExpire   time.Time `json:"token_expire"`
	EnvironmentID uint      `json:"environment_id"`
}
