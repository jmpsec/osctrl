package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// MFAChallengeResponse is what the first login step returns when a second
// factor is still owed. There is deliberately no token in it: the challenge id
// only names a half-finished login, and is worthless without the factor.
type MFAChallengeResponse struct {
	// MFARequired is true when the user has factors to present.
	MFARequired bool `json:"mfa_required"`
	// MFAEnrollmentRequired is true when the deployment requires MFA and
	// this user has none yet, so the second step is enrollment.
	MFAEnrollmentRequired bool   `json:"mfa_enrollment_required"`
	Challenge             string `json:"challenge"`
	// Methods lists what this user can answer with: "totp", "webauthn",
	// "recovery".
	Methods []string `json:"methods"`
}

// MFALoginRequest answers a login challenge with a code.
type MFALoginRequest struct {
	Challenge string `json:"challenge"`
	// Method is "totp" or "recovery".
	Method string `json:"method"`
	Code   string `json:"code"`
}

// MFAWebAuthnRequest carries a WebAuthn ceremony payload. Credential is the
// raw PublicKeyCredential JSON the browser produced, forwarded verbatim.
type MFAWebAuthnRequest struct {
	Challenge  string          `json:"challenge"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential" swaggertype:"object"`
}

// MFAEnrollRequest completes a forced enrollment at login time.
type MFAEnrollRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// MFAEnrollBeginResponse hands back a secret to load into an authenticator.
type MFAEnrollBeginResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	// QR is the provisioning URI as a PNG data URI, ready for an <img>.
	QR string `json:"qr,omitempty"`
}

// mfaChallengeResponse creates a challenge for a user who has just passed the
// password step and tells the client how it can be answered.
func (h *HandlersApi) mfaChallengeResponse(w http.ResponseWriter, r *http.Request, username, purpose string, expHours int) {
	challenge, err := h.MFA.NewChallenge(username, purpose, expHours)
	if err != nil {
		apiErrorResponse(w, "error starting mfa challenge", http.StatusInternalServerError, err)
		return
	}
	resp := MFAChallengeResponse{Challenge: challenge}
	if purpose == mfa.PurposeEnroll {
		resp.MFAEnrollmentRequired = true
		resp.Methods = []string{"totp"}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
		return
	}
	resp.MFARequired = true
	status, err := h.MFA.Status(username)
	if err != nil {
		apiErrorResponse(w, "error reading mfa status", http.StatusInternalServerError, err)
		return
	}
	if status.TOTPEnabled {
		resp.Methods = append(resp.Methods, "totp")
	}
	if len(status.Credentials) > 0 && h.WebAuthn != nil {
		resp.Methods = append(resp.Methods, "webauthn")
	}
	if status.RecoveryCodesLeft > 0 {
		resp.Methods = append(resp.Methods, "recovery")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// mfaFailed records a rejected second factor and answers with a deliberately
// vague error: the client already knows the password was right, and telling it
// which half of the check failed only helps an attacker.
func (h *HandlersApi) mfaFailed(w http.ResponseWriter, r *http.Request, username, reason string) {
	h.AuditLog.FailedLogin(username, utils.GetIP(r), reason)
	apiErrorResponse(w, "invalid multi-factor authentication", http.StatusForbidden, nil)
}

// LoginMFAHandler — POST /api/v1/login/mfa
//
// Second step of a password login, answered with a TOTP code or a recovery
// code. On success it consumes the challenge and mints the session.
// @Summary Complete a login with a second factor
// @Description Answers an MFA challenge with a TOTP or recovery code and returns a JWT token.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body MFALoginRequest true "Request body"
// @Success 200 {object} types.ApiLoginResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/login/mfa [post]
func (h *HandlersApi) LoginMFAHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if h.MFA == nil {
		apiErrorResponse(w, "mfa is not available", http.StatusNotFound, nil)
		return
	}
	var req MFALoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeLogin)
	if err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	switch req.Method {
	case "recovery":
		err = h.MFA.VerifyRecoveryCode(challenge.Username, req.Code)
	default:
		err = h.MFA.VerifyTOTP(challenge.Username, req.Code)
	}
	if err != nil {
		h.mfaFailed(w, r, challenge.Username, "invalid second factor")
		return
	}
	// Consume before minting: if two requests race with the same challenge,
	// only the one that claims it gets a session.
	if err := h.MFA.ConsumeChallenge(req.Challenge); err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	if req.Method == "recovery" {
		h.AuditLog.SettingsAction(challenge.Username, "mfa: signed in with a recovery code", utils.GetIP(r))
	}
	if err := h.issueSession(w, r, challenge.Username, challenge.ExpHours, nil); err != nil {
		apiErrorResponse(w, "error creating session", http.StatusInternalServerError, err)
	}
}

// LoginMFAWebAuthnBeginHandler — POST /api/v1/login/mfa/webauthn/begin
//
// Returns the assertion options for navigator.credentials.get().
// @Summary Begin a WebAuthn login ceremony
// @Description Returns WebAuthn assertion options for an MFA challenge.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body MFAWebAuthnRequest true "Request body"
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/login/mfa/webauthn/begin [post]
func (h *HandlersApi) LoginMFAWebAuthnBeginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if h.MFA == nil || h.WebAuthn == nil {
		apiErrorResponse(w, "webauthn is not available", http.StatusNotFound, nil)
		return
	}
	var req MFAWebAuthnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeLogin)
	if err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	assertion, session, err := h.WebAuthn.BeginLogin(challenge.Username)
	if err != nil {
		if errors.Is(err, mfa.ErrNotEnrolled) {
			apiErrorResponse(w, "no security keys registered", http.StatusForbidden, err)
			return
		}
		apiErrorResponse(w, "error starting webauthn login", http.StatusInternalServerError, err)
		return
	}
	// The ceremony state lives on the challenge row, so the browser cannot
	// tamper with it between begin and finish.
	if err := h.MFA.SetChallengeSession(req.Challenge, session, ""); err != nil {
		apiErrorResponse(w, "error storing webauthn session", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, assertion)
}

// LoginMFAWebAuthnFinishHandler — POST /api/v1/login/mfa/webauthn/finish
//
// Validates the assertion and mints the session.
// @Summary Finish a WebAuthn login ceremony
// @Description Validates a WebAuthn assertion and returns a JWT token.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body MFAWebAuthnRequest true "Request body"
// @Success 200 {object} types.ApiLoginResponse
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/login/mfa/webauthn/finish [post]
func (h *HandlersApi) LoginMFAWebAuthnFinishHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if h.MFA == nil || h.WebAuthn == nil {
		apiErrorResponse(w, "webauthn is not available", http.StatusNotFound, nil)
		return
	}
	var req MFAWebAuthnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeLogin)
	if err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	if challenge.SessionData == "" {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, nil)
		return
	}
	if err := h.WebAuthn.FinishLogin(challenge.Username, challenge.SessionData, req.Credential); err != nil {
		h.mfaFailed(w, r, challenge.Username, "webauthn assertion rejected")
		return
	}
	if err := h.MFA.ConsumeChallenge(req.Challenge); err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	if err := h.issueSession(w, r, challenge.Username, challenge.ExpHours, nil); err != nil {
		apiErrorResponse(w, "error creating session", http.StatusInternalServerError, err)
	}
}

// LoginMFAEnrollBeginHandler — POST /api/v1/login/mfa/enroll/begin
//
// Starts TOTP enrollment for a user the deployment requires MFA from. The
// secret is bound to the challenge rather than stored against the user, so an
// abandoned enrollment leaves nothing behind.
// @Summary Begin enrollment during login
// @Description Returns a TOTP secret for a user who must enroll before logging in.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body MFAEnrollRequest true "Request body"
// @Success 200 {object} MFAEnrollBeginResponse
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/login/mfa/enroll/begin [post]
func (h *HandlersApi) LoginMFAEnrollBeginHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if h.MFA == nil {
		apiErrorResponse(w, "mfa is not available", http.StatusNotFound, nil)
		return
	}
	var req MFAEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeEnroll)
	if err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		apiErrorResponse(w, "error generating secret", http.StatusInternalServerError, err)
		return
	}
	if err := h.MFA.SetChallengeSession(req.Challenge, "", secret); err != nil {
		apiErrorResponse(w, "error storing enrollment", http.StatusInternalServerError, err)
		return
	}
	uri := mfa.ProvisioningURI(h.mfaIssuer(), challenge.Username, secret)
	qr, err := mfa.QRDataURI(uri)
	if err != nil {
		log.Err(err).Msg("mfa: could not render enrollment QR code")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, MFAEnrollBeginResponse{
		Secret: secret,
		URI:    uri,
		QR:     qr,
	})
}

// LoginMFAEnrollFinishHandler — POST /api/v1/login/mfa/enroll/finish
//
// Confirms the enrollment with a code from the authenticator, stores the
// factor, and only then mints the session. Recovery codes come back with it.
// @Summary Finish enrollment during login
// @Description Confirms a TOTP enrollment and returns a JWT token plus recovery codes.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body MFAEnrollRequest true "Request body"
// @Success 200 {object} types.ApiLoginResponse
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Router /api/v1/login/mfa/enroll/finish [post]
func (h *HandlersApi) LoginMFAEnrollFinishHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if h.MFA == nil {
		apiErrorResponse(w, "mfa is not available", http.StatusNotFound, nil)
		return
	}
	var req MFAEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	challenge, err := h.MFA.GetChallenge(req.Challenge, mfa.PurposeEnroll)
	if err != nil || challenge.PendingSecret == "" {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	codes, err := h.MFA.CompleteEnrollment(challenge.Username, challenge.PendingSecret, req.Code)
	if err != nil {
		h.mfaFailed(w, r, challenge.Username, "invalid enrollment code")
		return
	}
	if err := h.MFA.ConsumeChallenge(req.Challenge); err != nil {
		apiErrorResponse(w, "invalid or expired challenge", http.StatusForbidden, err)
		return
	}
	h.AuditLog.SettingsAction(challenge.Username, "mfa: enrolled an authenticator app at login", utils.GetIP(r))
	extra := map[string]any{"recovery_codes": codes}
	if err := h.issueSession(w, r, challenge.Username, challenge.ExpHours, extra); err != nil {
		apiErrorResponse(w, "error creating session", http.StatusInternalServerError, err)
	}
}

// mfaIssuer is the label authenticator apps show. Falls back to the service
// name so a deployment that sets nothing still gets something recognizable.
func (h *HandlersApi) mfaIssuer() string {
	if h.MFAIssuer != "" {
		return h.MFAIssuer
	}
	return "osctrl"
}
