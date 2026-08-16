package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// MFAStatusResponse describes the factors on the caller's own account.
type MFAStatusResponse struct {
	// Required mirrors the deployment-wide switch so the profile page can
	// explain why a factor cannot be removed.
	Required          bool            `json:"required"`
	WebAuthnAvailable bool            `json:"webauthn_available"`
	TOTPEnabled       bool            `json:"totp_enabled"`
	RecoveryCodesLeft int             `json:"recovery_codes_left"`
	Credentials       []MFACredential `json:"credentials"`
}

// MFACredential is the API projection of a registered authenticator. The
// public key and AAGUID stay server-side; the SPA only needs to name it and
// address it for deletion.
type MFACredential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// MFATOTPBeginResponse carries the secret to load into an authenticator app.
type MFATOTPBeginResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	// QR is the provisioning URI as a PNG data URI, ready for an <img>.
	QR string `json:"qr,omitempty"`
}

// MFACodeRequest confirms an enrollment with a code from the app.
type MFACodeRequest struct {
	Code string `json:"code"`
}

// MFAPasswordRequest re-authenticates the caller before a change that weakens
// their account. A hijacked session should not be able to strip a factor.
type MFAPasswordRequest struct {
	Password string `json:"password"`
}

// MFARecoveryCodesResponse returns freshly minted recovery codes. This is the
// only time they exist in plaintext.
type MFARecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// mfaUser returns the caller's username, or "" after writing the error.
func (h *HandlersApi) mfaUser(w http.ResponseWriter, r *http.Request) string {
	if h.MFA == nil {
		apiErrorResponse(w, "mfa is not available", http.StatusNotFound, nil)
		return ""
	}
	ctx, ok := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !ok || ctx[ctxUser] == "" {
		apiErrorResponse(w, "unauthorized", http.StatusUnauthorized, nil)
		return ""
	}
	return ctx[ctxUser]
}

// confirmPassword re-checks the account password before a destructive change.
// Accounts with no password (federated logins that were JIT-provisioned) skip
// the check — there is nothing to re-enter, and refusing would strand them.
func (h *HandlersApi) confirmPassword(w http.ResponseWriter, r *http.Request, username string) bool {
	user, err := h.Users.Get(username)
	if err != nil {
		apiErrorResponse(w, "unauthorized", http.StatusUnauthorized, err)
		return false
	}
	if user.PassHash == "" {
		return true
	}
	var req MFAPasswordRequest
	// A malformed or absent body is treated as a missing password below.
	_ = json.NewDecoder(r.Body).Decode(&req)
	ok, _ := h.Users.CheckLoginCredentials(username, req.Password)
	if !ok {
		h.AuditLog.FailedLogin(username, utils.GetIP(r), "wrong password confirming an MFA change")
		apiErrorResponse(w, "password confirmation failed", http.StatusForbidden, nil)
		return false
	}
	return true
}

// MFAStatusHandler — GET /api/v1/mfa
// @Summary Multi-factor status
// @Description Returns the second factors enrolled on the calling account.
// @Tags mfa
// @Produce json
// @Success 200 {object} MFAStatusResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa [get]
func (h *HandlersApi) MFAStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	status, err := h.MFA.Status(username)
	if err != nil {
		apiErrorResponse(w, "error reading mfa status", http.StatusInternalServerError, err)
		return
	}
	creds := make([]MFACredential, 0, len(status.Credentials))
	for _, c := range status.Credentials {
		item := MFACredential{
			ID:        c.CredentialID,
			Name:      c.Name,
			CreatedAt: c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if c.LastUsedAt != nil {
			item.LastUsedAt = c.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		creds = append(creds, item)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, MFAStatusResponse{
		Required:          h.MFARequired,
		WebAuthnAvailable: h.WebAuthn != nil,
		TOTPEnabled:       status.TOTPEnabled,
		RecoveryCodesLeft: status.RecoveryCodesLeft,
		Credentials:       creds,
	})
}

// MFATOTPBeginHandler — POST /api/v1/mfa/totp
//
// Starts enrollment and returns the shared secret. Nothing is active until the
// verify step, so an abandoned QR code changes nothing.
// @Summary Begin TOTP enrollment
// @Description Generates a TOTP secret and provisioning URI for the calling account.
// @Tags mfa
// @Produce json
// @Success 200 {object} MFATOTPBeginResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/totp [post]
func (h *HandlersApi) MFATOTPBeginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	secret, err := h.MFA.BeginTOTP(username)
	if err != nil {
		apiErrorResponse(w, "authenticator app is already enrolled", http.StatusConflict, err)
		return
	}
	uri := mfa.ProvisioningURI(h.mfaIssuer(), username, secret)
	// A QR failure is not worth failing enrollment over: the secret can
	// always be typed in by hand.
	qr, err := mfa.QRDataURI(uri)
	if err != nil {
		log.Err(err).Msg("mfa: could not render enrollment QR code")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, MFATOTPBeginResponse{
		Secret: secret,
		URI:    uri,
		QR:     qr,
	})
}

// MFATOTPVerifyHandler — POST /api/v1/mfa/totp/verify
//
// Confirms enrollment and hands out recovery codes.
// @Summary Confirm TOTP enrollment
// @Description Verifies a code from the authenticator app and returns recovery codes.
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body MFACodeRequest true "Request body"
// @Success 200 {object} MFARecoveryCodesResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/totp/verify [post]
func (h *HandlersApi) MFATOTPVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	var req MFACodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	codes, err := h.MFA.ConfirmTOTP(username, req.Code)
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) || errors.Is(err, mfa.ErrNotEnrolled) {
			apiErrorResponse(w, "invalid code", http.StatusForbidden, err)
			return
		}
		apiErrorResponse(w, "error confirming enrollment", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(username, "mfa: enrolled an authenticator app", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, MFARecoveryCodesResponse{RecoveryCodes: codes})
}

// MFATOTPDeleteHandler — DELETE /api/v1/mfa/totp
//
// Removes the authenticator factor. Refused when the deployment requires MFA
// and this is the account's last factor: dropping it would lock the user out
// on their next login.
// @Summary Remove TOTP
// @Description Disables the authenticator-app factor after confirming the account password.
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body MFAPasswordRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/totp [delete]
func (h *HandlersApi) MFATOTPDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	if !h.confirmPassword(w, r, username) {
		return
	}
	status, err := h.MFA.Status(username)
	if err != nil {
		apiErrorResponse(w, "error reading mfa status", http.StatusInternalServerError, err)
		return
	}
	if h.MFARequired && len(status.Credentials) == 0 {
		apiErrorResponse(w, "multi-factor authentication is required — register a security key before removing the authenticator app", http.StatusConflict, nil)
		return
	}
	if err := h.MFA.DisableTOTP(username); err != nil {
		apiErrorResponse(w, "error removing authenticator", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(username, "mfa: removed the authenticator app", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "authenticator removed"})
}

// MFARecoveryHandler — POST /api/v1/mfa/recovery
//
// Replaces the recovery codes and returns the new set.
// @Summary Regenerate recovery codes
// @Description Invalidates the existing recovery codes and returns a new set.
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body MFAPasswordRequest true "Request body"
// @Success 200 {object} MFARecoveryCodesResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/recovery [post]
func (h *HandlersApi) MFARecoveryHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	if !h.confirmPassword(w, r, username) {
		return
	}
	if !h.MFA.Enabled(username) {
		apiErrorResponse(w, "no second factor is enrolled", http.StatusConflict, nil)
		return
	}
	codes, err := h.MFA.RegenerateRecoveryCodes(username)
	if err != nil {
		apiErrorResponse(w, "error generating recovery codes", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(username, "mfa: regenerated recovery codes", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, MFARecoveryCodesResponse{RecoveryCodes: codes})
}

// MFAWebAuthnBeginHandler — POST /api/v1/mfa/webauthn
//
// Starts registration of a passkey or security key for the calling user.
// @Summary Begin WebAuthn registration
// @Description Returns WebAuthn creation options for the calling account.
// @Tags mfa
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/webauthn [post]
func (h *HandlersApi) MFAWebAuthnBeginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	if h.WebAuthn == nil {
		apiErrorResponse(w, "webauthn is not available", http.StatusNotFound, nil)
		return
	}
	creation, session, err := h.WebAuthn.BeginRegistration(username)
	if err != nil {
		apiErrorResponse(w, "error starting registration", http.StatusInternalServerError, err)
		return
	}
	challenge, err := h.MFA.NewChallenge(username, mfa.PurposeRegister, 0)
	if err != nil {
		apiErrorResponse(w, "error starting registration", http.StatusInternalServerError, err)
		return
	}
	if err := h.MFA.SetChallengeSession(challenge, session, ""); err != nil {
		apiErrorResponse(w, "error storing registration session", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, map[string]any{
		"challenge_id": challenge,
		"options":      creation,
	})
}

// MFAWebAuthnFinishHandler — POST /api/v1/mfa/webauthn/verify
//
// Validates the attestation and stores the credential.
// @Summary Finish WebAuthn registration
// @Description Validates a WebAuthn attestation and stores the credential.
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body MFAWebAuthnRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/webauthn/verify [post]
func (h *HandlersApi) MFAWebAuthnFinishHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	if h.WebAuthn == nil {
		apiErrorResponse(w, "webauthn is not available", http.StatusNotFound, nil)
		return
	}
	var req MFAWebAuthnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeRegister)
	if err != nil || challenge.Username != username || challenge.SessionData == "" {
		apiErrorResponse(w, "invalid or expired registration", http.StatusForbidden, err)
		return
	}
	name := req.Name
	if name == "" {
		name = "Security key"
	}
	cred, err := h.WebAuthn.FinishRegistration(username, name, challenge.SessionData, req.Credential)
	if err != nil {
		apiErrorResponse(w, "could not register this authenticator", http.StatusForbidden, err)
		return
	}
	if err := h.MFA.ConsumeChallenge(req.Challenge); err != nil {
		apiErrorResponse(w, "invalid or expired registration", http.StatusForbidden, err)
		return
	}
	if err := h.MFA.AddCredential(cred); err != nil {
		apiErrorResponse(w, "error storing credential", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(username, "mfa: registered a security key or passkey", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "authenticator registered"})
}

// MFAWebAuthnDeleteHandler — DELETE /api/v1/mfa/webauthn/{id}
// @Summary Remove a WebAuthn credential
// @Description Deletes one registered passkey or security key after confirming the account password.
// @Tags mfa
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param request body MFAPasswordRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/mfa/webauthn/{id} [delete]
func (h *HandlersApi) MFAWebAuthnDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	username := h.mfaUser(w, r)
	if username == "" {
		return
	}
	if !h.confirmPassword(w, r, username) {
		return
	}
	status, err := h.MFA.Status(username)
	if err != nil {
		apiErrorResponse(w, "error reading mfa status", http.StatusInternalServerError, err)
		return
	}
	if h.MFARequired && !status.TOTPEnabled && len(status.Credentials) <= 1 {
		apiErrorResponse(w, "multi-factor authentication is required — enroll another factor before removing this one", http.StatusConflict, nil)
		return
	}
	if err := h.MFA.DeleteCredential(username, r.PathValue("id")); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "credential not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error removing credential", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(username, "mfa: removed a security key or passkey", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "authenticator removed"})
}
