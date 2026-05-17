package types

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/queries"
)

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

// LoginEnvironment is the pre-auth-safe projection of an environment returned
// by GET /api/v1/login/environments. UUID + name only — every other field
// stays behind auth.
type LoginEnvironment struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
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

// NodesPagedResponse is the SPA-canonical paginated response for GET /api/v1/nodes/{env}.
// Items are NodeView — OsqueryNode plus the optional `system_info` enrichment
// block (CPU cores, BIOS, hardware vendor/model) parsed from RawEnrollment.
// The embed keeps every previous OsqueryNode JSON field at the same key, so
// existing consumers (CLI, dashboards) are unaffected.
type NodesPagedResponse struct {
	Items      []NodeView `json:"items"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
	TotalItems int64      `json:"total_items"`
	TotalPages int        `json:"total_pages"`
}

// QueriesPagedResponse is the SPA-canonical paginated response for
// GET /api/v1/queries/{env}/list/{target}.
type QueriesPagedResponse struct {
	Items      []queries.DistributedQuery `json:"items"`
	Page       int                        `json:"page"`
	PageSize   int                        `json:"page_size"`
	TotalItems int64                      `json:"total_items"`
	TotalPages int                        `json:"total_pages"`
}

// QueryResultsResponse is the SPA-canonical paginated response for
// GET /api/v1/queries/{env}/results/{name}.
type QueryResultsResponse struct {
	Items      []map[string]any `json:"items"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalItems int64            `json:"total_items"`
	TotalPages int              `json:"total_pages"`
	Since      string           `json:"since,omitempty"`
}

// SavedQueryView is the SPA-canonical projection of a saved query.
// We use a hand-typed struct (rather than queries.SavedQuery directly) so the
// JSON envelope stays stable even if the storage struct gains fields.
// Timestamps are emitted as RFC3339 (Go time.Time default JSON encoding), to
// match the OpenAPI schema (date-time) and the SPA's formatRelative parser.
type SavedQueryView struct {
	ID            uint      `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Name          string    `json:"name"`
	Creator       string    `json:"creator"`
	Query         string    `json:"query"`
	EnvironmentID uint      `json:"environment_id"`
	ExtraData     string    `json:"extra_data,omitempty"`
}

// SavedQueriesPagedResponse is the SPA-canonical paginated response for
// GET /api/v1/saved-queries/{env}.
type SavedQueriesPagedResponse struct {
	Items      []SavedQueryView `json:"items"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalItems int64            `json:"total_items"`
	TotalPages int              `json:"total_pages"`
}

// SavedQueryCreateRequest is the body shape for POST /api/v1/saved-queries/{env}.
type SavedQueryCreateRequest struct {
	Name  string `json:"name"`
	Query string `json:"query"`
}

// SavedQueryUpdateRequest is the body shape for PATCH /api/v1/saved-queries/{env}/{name}.
type SavedQueryUpdateRequest struct {
	Query string `json:"query"`
}

// CarvesPagedResponse is the SPA-canonical paginated response for
// GET /api/v1/carves/{env}. Items are carve-type DistributedQuery rows
// (one per carve operation, regardless of how many nodes the carve targeted).
type CarvesPagedResponse struct {
	Items      []queries.DistributedQuery `json:"items"`
	Page       int                        `json:"page"`
	PageSize   int                        `json:"page_size"`
	TotalItems int64                      `json:"total_items"`
	TotalPages int                        `json:"total_pages"`
}

// CarveFileView is the SPA-canonical projection of a single carved file
// row (one per node that completed the carve). Timestamps are RFC3339 so
// the SPA's formatRelative parser handles them; CarveID is the disambiguator
// when downloading the archive of a multi-node carve.
type CarveFileView struct {
	CarveID         string    `json:"carve_id"`
	SessionID       string    `json:"session_id"`
	UUID            string    `json:"uuid"`
	Path            string    `json:"path"`
	Status          string    `json:"status"`
	CarveSize       int       `json:"carve_size"`
	BlockSize       int       `json:"block_size"`
	TotalBlocks     int       `json:"total_blocks"`
	CompletedBlocks int       `json:"completed_blocks"`
	Archived        bool      `json:"archived"`
	CreatedAt       time.Time `json:"created_at"`
	CompletedAt     time.Time `json:"completed_at"`
}

// CarveDetailResponse is the SPA-canonical response for
// GET /api/v1/carves/{env}/{name}. It pairs the carve QUERY metadata with
// the per-node CarvedFile rows produced by the carve.
type CarveDetailResponse struct {
	Query queries.DistributedQuery `json:"query"`
	Files []CarveFileView          `json:"files"`
}

// EnvAccessView mirrors users.EnvAccess but lives in the types package so
// the API request/response shapes don't pull in pkg/users for SPA-side codegen.
type EnvAccessView struct {
	User  bool `json:"user"`
	Query bool `json:"query"`
	Carve bool `json:"carve"`
	Admin bool `json:"admin"`
}

// SetPermissionsRequest is the body for POST /api/v1/users/{username}/permissions.
type SetPermissionsRequest struct {
	EnvUUID string        `json:"env_uuid"`
	Access  EnvAccessView `json:"access"`
}

// SetPermissionsAllRequest is the body for
// POST /api/v1/users/{username}/permissions/all — sets the same access
// shape across every environment currently in the system. No env_uuid;
// the server enumerates envs server-side.
//
// "All current envs" semantics: this applies to the env list at the
// time the request is handled. Envs created LATER do not inherit; the
// operator re-applies as needed.
type SetPermissionsAllRequest struct {
	Access EnvAccessView `json:"access"`
}

// GetPermissionsResponse is what
// GET /api/v1/users/{username}/permissions returns.
//
// Permissions maps env UUID → EnvAccessView. An env with no
// permission rows for the user is OMITTED — the SPA treats absence
// as "no access yet" (the default zero-value EnvAccess). Returning
// every env even with all-false rows would bloat responses for
// tenants with hundreds of envs without adding signal.
type GetPermissionsResponse struct {
	Username    string                   `json:"username"`
	Permissions map[string]EnvAccessView `json:"permissions"`
}

// SetPermissionsAllResponse is what
// POST /api/v1/users/{username}/permissions/all returns.
//
// Updated is the count of environments where the user's permissions
// were successfully (re-)written. Total is the count of envs the
// server iterated. On the happy path Updated == Total; if any single
// env's write failed mid-iteration the handler aborts the transaction
// and returns 5xx — partial-success is not exposed.
type SetPermissionsAllResponse struct {
	Updated int           `json:"updated"`
	Total   int           `json:"total"`
	Access  EnvAccessView `json:"access"`
}

// TokenResponse is returned by POST /api/v1/users/{username}/token/refresh
// and by login. The Token is shown ONCE to the operator (so they can copy it
// for CLI use); it isn't returned by any GET endpoint after refresh.
type TokenResponse struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// UserMeResponse is the SPA-canonical projection of the currently-authenticated
// user. Used by GET /api/v1/users/me.
type UserMeResponse struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Fullname    string    `json:"fullname"`
	Admin       bool      `json:"admin"`
	Service     bool      `json:"service"`
	UUID        string    `json:"uuid"`
	TokenExpire time.Time `json:"token_expire"`
	LastAccess  time.Time `json:"last_access"`
}

// UserMePatchRequest is the body for PATCH /api/v1/users/me — operators can
// update their own profile (email and fullname only).
type UserMePatchRequest struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname"`
}

// PasswordChangeRequest is the body for POST /api/v1/users/me/password.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ---------------------------------------------------------------------------
// Environments (Track 8)
// ---------------------------------------------------------------------------

// EnvCreateRequest is the body for POST /api/v1/environments.
type EnvCreateRequest struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Type     string `json:"type,omitempty"`
	Icon     string `json:"icon,omitempty"`
}

// EnvUpdateRequest is the body for PATCH /api/v1/environments/{env}.
// Pointer fields distinguish "unset" from "set to empty"; only supplied
// fields are written.
type EnvUpdateRequest struct {
	Name          *string `json:"name,omitempty"`
	Hostname      *string `json:"hostname,omitempty"`
	Type          *string `json:"type,omitempty"`
	Icon          *string `json:"icon,omitempty"`
	DebugHTTP     *bool   `json:"debug_http,omitempty"`
	AcceptEnrolls *bool   `json:"accept_enrolls,omitempty"`
}

// EnvConfigResponse is the GET /api/v1/environments/config/{env} payload —
// each field is the raw JSON string for that osquery config section so the
// SPA's Monaco editor can render and edit it as-is.
type EnvConfigResponse struct {
	Options    string `json:"options"`
	Schedule   string `json:"schedule"`
	Packs      string `json:"packs"`
	Decorators string `json:"decorators"`
	ATC        string `json:"atc"`
	Flags      string `json:"flags"`
}

// EnvConfigPatchRequest is the body for PATCH /api/v1/environments/config/{env}.
// Pointer fields: nil means "leave this section alone", non-nil writes it.
// Each non-nil value is JSON-validated before persisting; the handler rejects
// the whole payload if any section is invalid (no partial writes).
type EnvConfigPatchRequest struct {
	Options    *string `json:"options,omitempty"`
	Schedule   *string `json:"schedule,omitempty"`
	Packs      *string `json:"packs,omitempty"`
	Decorators *string `json:"decorators,omitempty"`
	ATC        *string `json:"atc,omitempty"`
	Flags      *string `json:"flags,omitempty"`
}

// EnvIntervalsPatchRequest is the body for PATCH /api/v1/environments/intervals/{env}.
// Each interval is in seconds; pointer semantics same as EnvConfigPatchRequest.
type EnvIntervalsPatchRequest struct {
	ConfigInterval *int `json:"config_interval,omitempty"`
	LogInterval    *int `json:"log_interval,omitempty"`
	QueryInterval  *int `json:"query_interval,omitempty"`
}

// EnvExpirationPatchRequest is the body for PATCH /api/v1/environments/expiration/{env}.
// Action is one of: extend, expire, rotate, not-expire.
type EnvExpirationPatchRequest struct {
	Action string `json:"action"`
}

// ---------------------------------------------------------------------------
// Settings (Track 9)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Audit log (Track 10)
// ---------------------------------------------------------------------------

// AuditLogView is the SPA-canonical projection of one pkg/auditlog.AuditLog row.
// We use a hand-typed struct (rather than the storage struct directly) so the
// JSON envelope stays stable as the storage shape evolves. Timestamps are
// RFC3339 to match SavedQueryView / CarveFileView and the SPA's formatRelative
// parser.
type AuditLogView struct {
	ID            uint      `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Service       string    `json:"service"`
	Username      string    `json:"username"`
	Line          string    `json:"line"`
	LogType       uint      `json:"log_type"`
	Severity      uint      `json:"severity"`
	SourceIP      string    `json:"source_ip"`
	EnvironmentID uint      `json:"environment_id"`
	EnvUUID       string    `json:"env_uuid,omitempty"`
}

// AuditLogsPagedResponse is the SPA-canonical paginated response for
// GET /api/v1/audit-logs.
type AuditLogsPagedResponse struct {
	Items      []AuditLogView `json:"items"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalItems int64          `json:"total_items"`
	TotalPages int            `json:"total_pages"`
}

// SettingPatchRequest is the body for PATCH /api/v1/settings/{service}/{name}.
// Exactly one of String / Boolean / Integer must be supplied; the handler
// validates the type matches what's stored. Type is informational and
// optional — when omitted the handler infers from the supplied field.
type SettingPatchRequest struct {
	Type    string  `json:"type,omitempty"`
	String  *string `json:"string,omitempty"`
	Boolean *bool   `json:"boolean,omitempty"`
	Integer *int64  `json:"integer,omitempty"`
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
	// AuthSource is empty for the password-login path (the default)
	// and "oidc" for users JIT-provisioned through the federated
	// callback. Surfaced so the SPA Users page can show an "OIDC"
	// badge alongside the existing admin/service labels.
	AuthSource string `json:"auth_source"`
}
