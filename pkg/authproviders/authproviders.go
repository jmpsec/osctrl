// Package authproviders persists federated authentication provider
// configurations (OIDC, SAML) to the database. Each row is one IdP
// configuration — multiple OIDC providers are supported, each rendered
// as a separate button on the login page.
//
// The package mirrors the pattern established by pkg/logsinks: a
// Registry maps each provider type to a typed field schema, a decode
// function, and a build function. The field schema drives the
// frontend's dynamic form. Secrets (OIDC client secret, SAML signing
// key PEM) are redacted in read responses and merged on edit.
//
// SAML signing keys can be auto-generated (self-signed RSA 2048-bit
// keypair) when the operator doesn't provide their own PEM — no files
// on disk needed.
package authproviders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auth"
	authoidc "github.com/jmpsec/osctrl/pkg/auth/oidc"
	authsaml "github.com/jmpsec/osctrl/pkg/auth/saml"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SourceService marks a row seeded from the resolved service configuration.
const SourceService = "service"

// SourceDB marks a row that has been edited or created through the API.
const SourceDB = "db"

// SourceYAML is retained for backwards compatibility.
const SourceYAML = "yaml"

// AuthProvider stores one IdP configuration. Config is a JSON-encoded
// blob whose shape is determined by Type and validated against the
// Registry. Multiple rows of the same Type are allowed — the login
// page renders one button per enabled row.
type AuthProvider struct {
	gorm.Model
	Name    string `gorm:"uniqueIndex"`
	Type    string `gorm:"index"` // "oidc" or "saml"
	Enabled bool
	Config  string `gorm:"type:text"` // JSON blob
	Source  string // "service" (seeded) or "db" (edited)
	Info    string
}

// AuthProviderManager manages the auth_providers table.
type AuthProviderManager struct {
	DB *gorm.DB
}

// NewAuthProviderManager initializes the manager and auto-migrates.
func NewAuthProviderManager(backend *gorm.DB) *AuthProviderManager {
	m := &AuthProviderManager{DB: backend}
	if err := backend.AutoMigrate(&AuthProvider{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (auth_providers): %v", err)
	}
	return m
}

// FieldType is the input kind the frontend should render.
type FieldType string

const (
	FieldString   FieldType = "string"
	FieldPassword FieldType = "password"
	FieldBoolean  FieldType = "boolean"
	FieldSelect   FieldType = "select"
	FieldInteger  FieldType = "integer"
	FieldText     FieldType = "text" // multiline
)

// FieldSpec describes one configurable field of a provider type.
type FieldSpec struct {
	Name        string
	Label       string
	Type        FieldType
	Required    bool
	Secret      bool
	Placeholder string
	Help        string
	Options     []string
	Default     any
}

// ProviderSpec describes one supported provider type in the Registry.
type ProviderSpec struct {
	Type         string
	Description  string
	HasSecret    bool
	SecretFields []string
	Fields       []FieldSpec
	// Decode unmarshals raw JSON Config into the typed config struct.
	Decode func(json.RawMessage) (any, error)
	// Build instantiates an auth.Provider from a decoded config.
	// The context is used for IdP discovery/metadata fetch.
	Build func(any, context.Context) (auth.Provider, error)
}

// Registry maps each provider type to its ProviderSpec.
var Registry = map[string]ProviderSpec{
	config.AuthOIDC: {
		Type:         config.AuthOIDC,
		Description:  "OpenID Connect (OAuth2 + OIDC Core). Multi-provider: one button per enabled row.",
		HasSecret:    true,
		SecretFields: []string{"ClientSecret"},
		Fields: []FieldSpec{
			{Name: "IssuerURL", Label: "Issuer URL", Type: FieldString, Required: true, Placeholder: "https://keycloak.example.com/realms/myrealm", Help: "OIDC issuer URL. The provider does discovery against /.well-known/openid-configuration."},
			{Name: "ClientID", Label: "Client ID", Type: FieldString, Required: true, Placeholder: "osctrl-client"},
			{Name: "ClientSecret", Label: "Client secret", Type: FieldPassword, Secret: true, Placeholder: "prefer env vars/secrets in prod", Help: "OIDC client secret. Required unless UsePKCE is true."},
			{Name: "RedirectURL", Label: "Redirect URL", Type: FieldString, Required: true, Placeholder: "https://osctrl.example.com:8444/api/v1/auth/oidc/{id}/callback", Help: "Callback URL registered with the IdP. {id} is replaced with the provider row ID at runtime."},
			{Name: "Scopes", Label: "Scopes", Type: FieldString, Placeholder: "openid,profile,email", Help: "Comma-separated. 'openid' is always prepended if absent."},
			{Name: "UsernameClaim", Label: "Username claim", Type: FieldSelect, Options: []string{"preferred_username", "email", "sub"}, Default: "preferred_username", Help: "OIDC claim used as the AdminUser.Username."},
			{Name: "GroupsClaim", Label: "Groups claim", Type: FieldString, Placeholder: "groups", Help: "OIDC claim consulted for group membership."},
			{Name: "RequiredGroups", Label: "Required groups", Type: FieldString, Placeholder: "osctrl-admins", Help: "Comma-separated. At least one must be present for login to succeed. Empty disables the gate."},
			{Name: "JITProvision", Label: "JIT provision", Type: FieldBoolean, Default: false, Help: "Auto-create an AdminUser on first successful login."},
			{Name: "UsePKCE", Label: "Use PKCE", Type: FieldBoolean, Default: false, Help: "Enable PKCE (RFC 7636). Recommended for public clients."},
		},
		Decode: decodeOIDCConfig,
		Build:  buildOIDCProvider,
	},
	config.AuthSAML: {
		Type:         config.AuthSAML,
		Description:  "SAML 2.0 Web Browser SSO. SP signing keys auto-generated when not provided.",
		HasSecret:    true,
		SecretFields: []string{"SigningKeyPEM"},
		Fields: []FieldSpec{
			{Name: "IDPMetadataURL", Label: "IdP metadata URL", Type: FieldString, Placeholder: "https://idp.example.com/metadata", Help: "IdP's published SAML metadata document URL. One of URL or XML below is required."},
			{Name: "IDPMetadataXML", Label: "IdP metadata XML", Type: FieldText, Placeholder: "<EntityDescriptor ...>", Help: "Inline IdP metadata XML (air-gapped deployments). Mutually exclusive with URL."},
			{Name: "EntityID", Label: "Entity ID", Type: FieldString, Required: true, Placeholder: "https://osctrl.example.com:8444/api/v1/auth/saml/{id}/metadata", Help: "SP entity identifier. {id} is replaced at runtime."},
			{Name: "ACSURL", Label: "ACS URL", Type: FieldString, Required: true, Placeholder: "https://osctrl.example.com:8444/api/v1/auth/saml/{id}/acs", Help: "Assertion Consumer Service URL. {id} is replaced at runtime."},
			{Name: "UsernameAttribute", Label: "Username attribute", Type: FieldString, Placeholder: "", Help: "SAML attribute whose value becomes the username. Empty = use NameID."},
			{Name: "GroupsAttribute", Label: "Groups attribute", Type: FieldString, Placeholder: "groups", Help: "SAML attribute carrying group memberships."},
			{Name: "RequiredGroups", Label: "Required groups", Type: FieldString, Placeholder: "osctrl-admins", Help: "Comma-separated. Empty disables the gate."},
			{Name: "JITProvision", Label: "JIT provision", Type: FieldBoolean, Default: false, Help: "Auto-create an AdminUser on first successful login."},
			{Name: "SigningCertPEM", Label: "SP signing cert (PEM)", Type: FieldText, Placeholder: "-----BEGIN CERTIFICATE-----", Help: "Optional. Leave empty to auto-generate a self-signed keypair."},
			{Name: "SigningKeyPEM", Label: "SP signing key (PEM)", Type: FieldPassword, Secret: true, Placeholder: "-----BEGIN RSA PRIVATE KEY-----", Help: "Optional. Leave empty to auto-generate."},
			{Name: "ForceAuthn", Label: "Force Authn", Type: FieldBoolean, Default: true, Help: "Re-prompt for credentials even if IdP SSO cookie is alive."},
			{Name: "RequireAssertionSigned", Label: "Require signed assertion", Type: FieldBoolean, Default: true, Help: "Must be true for production (threat S2 defense)."},
			{Name: "ReplayWindow", Label: "Replay window (min)", Type: FieldInteger, Default: 5, Help: "Maximum clock skew on NotBefore/NotOnOrAfter checks."},
		},
		Decode: decodeSAMLConfig,
		Build:  buildSAMLProvider,
	},
}

// SupportedTypes returns the Registry keys in sorted order.
func SupportedTypes() []string {
	types := make([]string, 0, len(Registry))
	for k := range Registry {
		types = append(types, k)
	}
	for i := 1; i < len(types); i++ {
		for j := i; j > 0 && types[j-1] > types[j]; j-- {
			types[j-1], types[j] = types[j], types[j-1]
		}
	}
	return types
}

// ValidateType reports whether the provider type is registered.
func ValidateType(typ string) bool {
	_, ok := Registry[strings.ToLower(strings.TrimSpace(typ))]
	return ok
}

// --- decode functions ---

func decodeOIDCConfig(raw json.RawMessage) (any, error) {
	var c authoidc.Config
	if len(raw) == 0 || string(raw) == "null" {
		return &c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode oidc config: %w", err)
	}
	// Scopes may come as a comma-separated string from the form.
	// The oidc.Config expects []string. Handle both shapes.
	if len(c.Scopes) == 0 {
		var rawScopes struct {
			Scopes string `json:"Scopes"`
		}
		_ = json.Unmarshal(raw, &rawScopes)
		if rawScopes.Scopes != "" {
			for _, s := range strings.Split(rawScopes.Scopes, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					c.Scopes = append(c.Scopes, s)
				}
			}
		}
	}
	// RequiredGroups may come as comma-separated string.
	if len(c.RequiredGroups) == 0 {
		var rawGroups struct {
			RequiredGroups string `json:"RequiredGroups"`
		}
		_ = json.Unmarshal(raw, &rawGroups)
		if rawGroups.RequiredGroups != "" {
			for _, g := range strings.Split(rawGroups.RequiredGroups, ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					c.RequiredGroups = append(c.RequiredGroups, g)
				}
			}
		}
	}
	return &c, nil
}

func decodeSAMLConfig(raw json.RawMessage) (any, error) {
	var c authsaml.Config
	if len(raw) == 0 || string(raw) == "null" {
		return &c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode saml config: %w", err)
	}
	// RequiredGroups may come as comma-separated string.
	if len(c.RequiredGroups) == 0 {
		var rawGroups struct {
			RequiredGroups string `json:"RequiredGroups"`
		}
		_ = json.Unmarshal(raw, &rawGroups)
		if rawGroups.RequiredGroups != "" {
			for _, g := range strings.Split(rawGroups.RequiredGroups, ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					c.RequiredGroups = append(c.RequiredGroups, g)
				}
			}
		}
	}
	// RequireAssertionSigned defaults to true.
	if !c.RequireAssertionSigned {
		// Check if it was explicitly set to false or just zero.
		// We always force it to true for security — Validate() rejects false anyway.
		c.RequireAssertionSigned = true
	}
	return &c, nil
}

// --- build functions ---

func buildOIDCProvider(cfg any, ctx context.Context) (auth.Provider, error) {
	return authoidc.NewOIDCProvider(ctx, *cfg.(*authoidc.Config))
}

func buildSAMLProvider(cfg any, ctx context.Context) (auth.Provider, error) {
	return authsaml.NewSAMLProvider(ctx, *cfg.(*authsaml.Config))
}

// --- errors ---

var (
	ErrProviderNotFound      = errors.New("auth provider not found")
	ErrInvalidProviderType   = errors.New("invalid auth provider type")
	ErrInvalidProviderConfig = errors.New("invalid auth provider configuration")
)

// --- CRUD ---

func normalizeType(typ string) string {
	return strings.ToLower(strings.TrimSpace(typ))
}

func normalizeName(name string) string {
	return strings.TrimSpace(name)
}

func validateConfig(typ, cfgJSON string) (any, error) {
	spec, ok := Registry[typ]
	if !ok {
		return nil, ErrInvalidProviderType
	}
	raw := json.RawMessage(cfgJSON)
	if len(raw) == 0 {
		raw = json.RawMessage(`null`)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%w: not valid JSON", ErrInvalidProviderConfig)
	}
	decoded, err := spec.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProviderConfig, err)
	}
	return decoded, nil
}

func ValidateProvider(name, typ, cfgJSON string) error {
	if normalizeName(name) == "" {
		return fmt.Errorf("provider name is required")
	}
	t := normalizeType(typ)
	if !ValidateType(t) {
		return fmt.Errorf("%w: %q", ErrInvalidProviderType, typ)
	}
	if _, err := validateConfig(t, cfgJSON); err != nil {
		return err
	}
	return nil
}

// Create inserts a new provider row.
func (m *AuthProviderManager) Create(name, typ string, enabled bool, cfgJSON string, info string) (AuthProvider, error) {
	name = normalizeName(name)
	typ = normalizeType(typ)
	if err := ValidateProvider(name, typ, cfgJSON); err != nil {
		return AuthProvider{}, err
	}
	row := AuthProvider{
		Name:    name,
		Type:    typ,
		Enabled: enabled,
		Config:  cfgJSON,
		Source:  SourceDB,
		Info:    info,
	}
	if err := m.DB.Create(&row).Error; err != nil {
		return AuthProvider{}, fmt.Errorf("create auth provider: %w", err)
	}
	return row, nil
}

// Update replaces an existing provider row's mutable fields.
func (m *AuthProviderManager) Update(id uint, name, typ string, enabled bool, cfgJSON string, info string) (AuthProvider, error) {
	name = normalizeName(name)
	typ = normalizeType(typ)
	if err := ValidateProvider(name, typ, cfgJSON); err != nil {
		return AuthProvider{}, err
	}
	row, err := m.Get(id)
	if err != nil {
		return AuthProvider{}, err
	}
	if err := m.DB.Model(&row).Updates(map[string]any{
		"name":    name,
		"type":    typ,
		"enabled": enabled,
		"config":  cfgJSON,
		"info":    info,
		"source":  SourceDB,
	}).Error; err != nil {
		return AuthProvider{}, fmt.Errorf("update auth provider: %w", err)
	}
	return m.Get(id)
}

// Get retrieves one provider by ID.
func (m *AuthProviderManager) Get(id uint) (AuthProvider, error) {
	var row AuthProvider
	if err := m.DB.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return AuthProvider{}, ErrProviderNotFound
		}
		return AuthProvider{}, err
	}
	return row, nil
}

// Delete removes a provider by ID.
func (m *AuthProviderManager) Delete(id uint) error {
	res := m.DB.Delete(&AuthProvider{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// List returns all providers.
func (m *AuthProviderManager) List() ([]AuthProvider, error) {
	var rows []AuthProvider
	if err := m.DB.Order("\"type\" ASC, name ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ListEnabled returns all enabled providers.
func (m *AuthProviderManager) ListEnabled() ([]AuthProvider, error) {
	var rows []AuthProvider
	if err := m.DB.Where("enabled = ?", true).Order("\"type\" ASC, name ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// RevertToService flips a row's Source from "db" back to "service".
func (m *AuthProviderManager) RevertToService(id uint) error {
	row, err := m.Get(id)
	if err != nil {
		return err
	}
	if row.Source != SourceDB {
		return nil
	}
	if err := m.DB.Model(&row).Update("source", SourceService).Error; err != nil {
		return fmt.Errorf("revert auth provider %d: %w", id, err)
	}
	return nil
}

// --- seed ---

// Seed translates the resolved service configuration (OIDC and SAML
// sections) into AuthProvider rows using create-if-missing semantics.
func (m *AuthProviderManager) Seed(params *config.ServiceParameters) error {
	if params.OIDC != nil && params.OIDC.Enabled {
		cfg, err := oidcConfigFromYAML(params.OIDC)
		if err != nil {
			return err
		}
		cfgJSON, _ := json.Marshal(cfg)
		row := AuthProvider{
			Name:    "seeded-oidc",
			Type:    config.AuthOIDC,
			Enabled: true,
			Config:  string(cfgJSON),
			Source:  SourceService,
			Info:    "Seeded from service configuration",
		}
		if err := m.seedRow(&row); err != nil {
			return err
		}
	}
	if params.SAML != nil && params.SAML.Enabled {
		cfg := samlConfigFromYAML(params.SAML)
		cfgJSON, _ := json.Marshal(cfg)
		row := AuthProvider{
			Name:    "seeded-saml",
			Type:    config.AuthSAML,
			Enabled: true,
			Config:  string(cfgJSON),
			Source:  SourceService,
			Info:    "Seeded from service configuration",
		}
		if err := m.seedRow(&row); err != nil {
			return err
		}
	}
	return nil
}

func oidcConfigFromYAML(y *config.YAMLConfigurationOIDC) (authoidc.Config, error) {
	return authoidc.Config{
		IssuerURL:      y.IssuerURL,
		ClientID:       y.ClientID,
		ClientSecret:   y.ClientSecret,
		RedirectURL:    y.RedirectURL,
		Scopes:         y.Scopes,
		UsernameClaim:  y.UsernameClaim,
		GroupsClaim:    y.GroupsClaim,
		RequiredGroups: y.RequiredGroups,
		JITProvision:   y.JITProvision,
		UsePKCE:        y.UsePKCE,
	}, nil
}

func samlConfigFromYAML(y *config.YAMLConfigurationSAML) authsaml.Config {
	return authsaml.Config{
		IDPMetadataURL:         y.MetaDataURL,
		EntityID:               y.EntityID,
		ACSURL:                 y.ACSURL,
		UsernameAttribute:      y.UsernameAttribute,
		JITProvision:           y.JITProvision,
		ForceAuthn:             y.ForceAuthn,
		SigningCertPath:        y.SigningCertPath,
		SigningKeyPath:         y.SigningKeyPath,
		RequireAssertionSigned: true,
	}
}

// seedRow creates a row only if it doesn't exist, then syncs config
// for existing non-DB-edited rows.
func (m *AuthProviderManager) seedRow(row *AuthProvider) error {
	if err := m.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error; err != nil {
		return fmt.Errorf("seed row %q: %w", row.Name, err)
	}
	if err := m.DB.Model(&AuthProvider{}).
		Where("name = ? AND (source = ? OR source = ?)",
			row.Name, SourceService, SourceYAML).
		Updates(map[string]any{
			"config": row.Config,
			"type":   row.Type,
			"info":   row.Info,
		}).Error; err != nil {
		return fmt.Errorf("sync seed row %q: %w", row.Name, err)
	}
	return nil
}

// --- build providers from DB ---

// ProviderEntry is one built provider with its metadata.
type ProviderEntry struct {
	ID           uint
	Name         string
	Type         string
	Provider     auth.Provider
	JITProvision bool
	ClientID     string // OIDC only
	LogoutURL    string // SAML only
}

// BuildProviders reads all enabled rows, builds live auth.Provider
// instances, and returns them. Fail-fast: if any enabled provider's
// Build fails, the error is returned so the caller can log.Fatal.
func (m *AuthProviderManager) BuildProviders(ctx context.Context) ([]ProviderEntry, error) {
	rows, err := m.ListEnabled()
	if err != nil {
		return nil, err
	}
	var entries []ProviderEntry
	for _, row := range rows {
		spec, ok := Registry[row.Type]
		if !ok {
			return nil, fmt.Errorf("unknown provider type %q for row %q", row.Type, row.Name)
		}
		decoded, err := spec.Decode(json.RawMessage(row.Config))
		if err != nil {
			return nil, fmt.Errorf("decode config for %q: %w", row.Name, err)
		}
		// Expand {id} in SAML URLs with the actual row ID.
		if row.Type == config.AuthSAML {
			if cfg, ok := decoded.(*authsaml.Config); ok {
				cfg.EntityID = strings.ReplaceAll(cfg.EntityID, "{id}", fmt.Sprintf("%d", row.ID))
				cfg.ACSURL = strings.ReplaceAll(cfg.ACSURL, "{id}", fmt.Sprintf("%d", row.ID))
			}
		}
		if row.Type == config.AuthOIDC {
			if cfg, ok := decoded.(*authoidc.Config); ok {
				cfg.RedirectURL = strings.ReplaceAll(cfg.RedirectURL, "{id}", fmt.Sprintf("%d", row.ID))
			}
		}
		p, err := spec.Build(decoded, ctx)
		if err != nil {
			return nil, fmt.Errorf("build provider %q: %w", row.Name, err)
		}
		entry := ProviderEntry{
			ID:       row.ID,
			Name:     row.Name,
			Type:     row.Type,
			Provider: p,
		}
		// Extract type-specific fields for the handlers.
		if cfg, ok := decoded.(*authoidc.Config); ok {
			entry.JITProvision = cfg.JITProvision
			entry.ClientID = cfg.ClientID
		}
		if cfg, ok := decoded.(*authsaml.Config); ok {
			entry.JITProvision = cfg.JITProvision
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// --- redaction ---

// RedactedConfig replaces secret fields with "***" for the provider Type.
func RedactedConfig(typ, cfgJSON string) string {
	spec, ok := Registry[typ]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return cfgJSON
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &obj); err != nil {
		return cfgJSON
	}
	for _, key := range spec.SecretFields {
		if _, present := obj[key]; present {
			obj[key] = "***"
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return cfgJSON
	}
	return string(out)
}

// MergeSecrets replaces "***" placeholders with values from prev.
func MergeSecrets(typ, prevJSON, newJSON string) (string, error) {
	spec, ok := Registry[typ]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return newJSON, nil
	}
	var prev, next map[string]any
	if err := json.Unmarshal([]byte(prevJSON), &prev); err != nil {
		return "", fmt.Errorf("decode prev config: %w", err)
	}
	if err := json.Unmarshal([]byte(newJSON), &next); err != nil {
		return "", fmt.Errorf("decode new config: %w", err)
	}
	for _, key := range spec.SecretFields {
		v, ok := next[key]
		if !ok {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		if s == "***" || s == "" {
			if pv, pok := prev[key]; pok {
				next[key] = pv
			}
		}
	}
	out, err := json.Marshal(next)
	if err != nil {
		return "", fmt.Errorf("encode merged config: %w", err)
	}
	return string(out), nil
}

// --- test helper: persist auto-generated SAML keys back to DB ---

// PersistGeneratedSAMLKeys checks if a SAML provider row has
// auto-generated signing keys (both SigningCertPEM and SigningKeyPEM
// empty). After Build, the SAML provider has generated keys in
// memory. This function marshals the generated PEM back into the
// config JSON so the keys are stable across reloads. It only writes
// when the row's Source is NOT "db" (seed rows get the keys pinned;
// operator-edited rows keep whatever the operator set).
func (m *AuthProviderManager) PersistGeneratedSAMLKeys(row AuthProvider, certPEM, keyPEM string) error {
	if row.Type != config.AuthSAML || (certPEM == "" && keyPEM == "") {
		return nil
	}
	var cfg authsaml.Config
	if err := json.Unmarshal([]byte(row.Config), &cfg); err != nil {
		return fmt.Errorf("unmarshal saml config: %w", err)
	}
	if cfg.SigningCertPEM != "" || cfg.SigningKeyPEM != "" {
		return nil // operator provided their own PEM
	}
	cfg.SigningCertPEM = certPEM
	cfg.SigningKeyPEM = keyPEM
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal saml config with keys: %w", err)
	}
	return m.DB.Model(&AuthProvider{}).
		Where("id = ? AND (source = ? OR source = ?)", row.ID, SourceService, SourceYAML).
		Update("config", string(cfgJSON)).Error
}
