package handlers

// LoginRequest to receive login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LogoutRequest to receive logout requests
type LogoutRequest struct {
	CSRFToken string `json:"csrftoken"`
}

// DistributedQueryRequest to receive query requests
type DistributedQueryRequest struct {
	CSRFToken    string   `json:"csrftoken"`
	Environments []string `json:"environment_list"`
	Platforms    []string `json:"platform_list"`
	UUIDs        []string `json:"uuid_list"`
	Hosts        []string `json:"host_list"`
	Save         bool     `json:"save"`
	Name         string   `json:"name"`
	Query        string   `json:"query"`
}

// DistributedCarveRequest to receive carve requests
type DistributedCarveRequest struct {
	CSRFToken    string   `json:"csrftoken"`
	Environments []string `json:"environment_list"`
	Platforms    []string `json:"platform_list"`
	UUIDs        []string `json:"uuid_list"`
	Hosts        []string `json:"host_list"`
	Path         string   `json:"path"`
}

// DistributedQueryActionRequest to receive query requests
type DistributedQueryActionRequest struct {
	CSRFToken string   `json:"csrftoken"`
	Names     []string `json:"names"`
	Action    string   `json:"action"`
}

// DistributedCarvesActionRequest to receive carves requests
type DistributedCarvesActionRequest struct {
	CSRFToken string   `json:"csrftoken"`
	IDs       []string `json:"ids"`
	Action    string   `json:"action"`
}

// NodeMultiActionRequest to receive node action requests
type NodeMultiActionRequest struct {
	CSRFToken string   `json:"csrftoken"`
	Action    string   `json:"action"`
	UUIDs     []string `json:"uuids"`
}

// SettingsRequest to receive changes to settings
type SettingsRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Boolean   bool   `json:"boolean"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Value     string `json:"value"`
}

// ConfigurationRequest to receive changes to configuration
type ConfigurationRequest struct {
	CSRFToken        string `json:"csrftoken"`
	ConfigurationB64 string `json:"configuration"`
	OptionsB64       string `json:"options"`
	ScheduleB64      string `json:"schedule"`
	PacksB64         string `json:"packs"`
	DecoratorsB64    string `json:"decorators"`
	ATCB64           string `json:"atc"`
}

// EnrollRequest to receive changes to enroll certificates
type EnrollRequest struct {
	CSRFToken      string `json:"csrftoken"`
	CertificateB64 string `json:"certificate"`
}

// IntervalsRequest to receive changes to intervals
type IntervalsRequest struct {
	CSRFToken      string `json:"csrftoken"`
	ConfigInterval int    `json:"config"`
	LogInterval    int    `json:"log"`
	QueryInterval  int    `json:"query"`
}

// ExpirationRequest to receive expiration changes to enroll/remove nodes
type ExpirationRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Type      string `json:"type"`
}

// EnvironmentsRequest to receive changes to environments
type EnvironmentsRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	Type      string `json:"type"`
	Icon      string `json:"icon"`
	DebugHTTP bool   `json:"debughttp"`
}

// UsersRequest to receive user action requests
type UsersRequest struct {
	CSRFToken    string   `json:"csrftoken"`
	Action       string   `json:"action"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	Fullname     string   `json:"fullname"`
	OldPassword  string   `json:"old_password"`
	NewPassword  string   `json:"new_password"`
	Token        bool     `json:"token"`
	Admin        bool     `json:"admin"`
	Environments []string `json:"environments"`
}

// TagsRequest to receive tag action requests
type TagsRequest struct {
	CSRFToken   string `json:"csrftoken"`
	Action      string `json:"action"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Icon        string `json:"icon"`
}

// TagNodesRequest to receive a tag for nodes
type TagNodesRequest struct {
	CSRFToken  string   `json:"csrftoken"`
	UUIDs      []string `json:"uuids"`
	TagsAdd    []string `json:"tagsadd"`
	TagsRemove []string `json:"tagsremove"`
}

// PermissionsRequest to receive user permissions changes requests
type PermissionsRequest struct {
	CSRFToken   string `json:"csrftoken"`
	Environment string `json:"environment"`
	Read        bool   `json:"read"`
	Query       bool   `json:"query"`
	Carve       bool   `json:"carve"`
	Admin       bool   `json:"admin"`
}

// AdminResponse to be returned to requests
type AdminResponse struct {
	Message string `json:"message"`
}

// TokenRequest to receive API token related requests
type TokenRequest struct {
	CSRFToken string `json:"csrftoken"`
	Username  string `json:"username"`
}

// TokenResponse to be returned to API token requests
type TokenResponse struct {
	Token        string `json:"token"`
	Expiration   string `json:"expiration"`
	ExpirationTS string `json:"exp_ts"`
}

// ProfileRequest to receive user profile changes requests
type ProfileRequest struct {
	CSRFToken string `json:"csrftoken"`
	Username  string `json:"username"`
}

// SavedQueryRequest to receive saved query requests
type SavedQueryRequest struct {
	CSRFToken string `json:"csrftoken"`
	Action    string `json:"action"`
	Name      string `json:"name"`
	Query     string `json:"query"`
}
