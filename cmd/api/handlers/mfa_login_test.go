package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/users"
)

// mfaTestHandlers builds a HandlersApi backed by an in-memory database with
// one enrolled user, which is enough to drive the two-step login end to end.
func mfaTestHandlers(t *testing.T, required bool) (*HandlersApi, *mfa.Manager, *users.UserManager) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&users.AdminUser{}, &mfa.TOTPEnrollment{}, &mfa.RecoveryCode{},
		&mfa.Credential{}, &mfa.Challenge{}, &auditlog.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	secret := "test-jwt-secret-must-be-at-least-32-bytes-long"
	userManager := users.CreateUserManager(db).WithJWT(&config.YAMLConfigurationJWT{JWTSecret: secret, HoursToExpire: 3})
	newTestUser(t, userManager, "admin", false)
	auditManager, err := auditlog.CreateAuditLogManager(db, "osctrl-api-test", false)
	if err != nil {
		t.Fatalf("audit manager: %v", err)
	}
	mfaManager := &mfa.Manager{DB: db}
	h := &HandlersApi{
		DB:              db,
		Users:           userManager,
		AuditLog:        auditManager,
		MFA:             mfaManager,
		MFARequired:     required,
		ServiceName:     "osctrl-api-test",
		JWTSecret:       []byte(secret),
		DebugHTTPConfig: &config.YAMLConfigurationDebug{},
	}
	return h, mfaManager, userManager
}

// newTestUser creates and persists a user with a known password.
func newTestUser(t *testing.T, manager *users.UserManager, username string, service bool) {
	t.Helper()
	user, err := manager.New(username, "s3cr3t-password", username+"@example.com", username, !service, service)
	if err != nil {
		t.Fatalf("build user %s: %v", username, err)
	}
	if err := manager.Create(user); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
}

func postJSON(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func enrollTOTP(t *testing.T, m *mfa.Manager, username string) string {
	t.Helper()
	secret, err := m.BeginTOTP(username)
	if err != nil {
		t.Fatalf("begin totp: %v", err)
	}
	code, err := mfa.Code(secret, mfa.Step(time.Now()))
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if _, err := m.ConfirmTOTP(username, code); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	return secret
}

// The password step alone must not hand out a session for an enrolled user.
func TestLoginWithMFAReturnsChallengeNotToken(t *testing.T) {
	h, m, _ := mfaTestHandlers(t, false)
	enrollTOTP(t, m, "admin")

	w := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
		"username": "admin", "password": "s3cr3t-password",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp MFAChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.MFARequired || resp.Challenge == "" {
		t.Fatalf("expected an MFA challenge, got %+v", resp)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("no session cookie may be set before the second factor")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["token"]; ok {
		t.Fatalf("first step must not return a token: %v", body)
	}
}

func TestLoginMFACompletesWithTOTPAndRejectsReuse(t *testing.T) {
	h, m, _ := mfaTestHandlers(t, false)
	secret := enrollTOTP(t, m, "admin")

	first := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
		"username": "admin", "password": "s3cr3t-password", "exp_hours": 2,
	})
	var challenge MFAChallengeResponse
	if err := json.Unmarshal(first.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// A wrong code is refused without burning the challenge.
	bad := postJSON(t, h.LoginMFAHandler, "/api/v1/login/mfa", map[string]any{
		"challenge": challenge.Challenge, "method": "totp", "code": "000000",
	})
	if bad.Code != http.StatusForbidden {
		t.Fatalf("wrong code status: got %d want 403", bad.Code)
	}

	code, err := mfa.Code(secret, mfa.Step(time.Now())+1)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	good := postJSON(t, h.LoginMFAHandler, "/api/v1/login/mfa", map[string]any{
		"challenge": challenge.Challenge, "method": "totp", "code": code,
	})
	if good.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (%s)", good.Code, good.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(good.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session["token"] == "" || session["csrf_token"] == "" {
		t.Fatalf("expected a token and csrf token, got %v", session)
	}
	var sawSession bool
	for _, c := range good.Result().Cookies() {
		if c.Name == "osctrl_token" && c.Value != "" {
			sawSession = true
		}
	}
	if !sawSession {
		t.Fatalf("expected the session cookie to be set")
	}

	// The challenge is single-use, so a replayed request gets nothing.
	replay := postJSON(t, h.LoginMFAHandler, "/api/v1/login/mfa", map[string]any{
		"challenge": challenge.Challenge, "method": "totp", "code": code,
	})
	if replay.Code == http.StatusOK {
		t.Fatalf("a consumed challenge must not mint a second session")
	}
}

func TestLoginMFAAcceptsRecoveryCodeOnce(t *testing.T) {
	h, m, _ := mfaTestHandlers(t, false)
	enrollTOTP(t, m, "admin")
	codes, err := m.RegenerateRecoveryCodes("admin")
	if err != nil {
		t.Fatalf("recovery codes: %v", err)
	}

	login := func() string {
		w := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
			"username": "admin", "password": "s3cr3t-password",
		})
		var resp MFAChallengeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.Challenge
	}

	ok := postJSON(t, h.LoginMFAHandler, "/api/v1/login/mfa", map[string]any{
		"challenge": login(), "method": "recovery", "code": codes[0],
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("recovery login: got %d want 200 (%s)", ok.Code, ok.Body.String())
	}
	reuse := postJSON(t, h.LoginMFAHandler, "/api/v1/login/mfa", map[string]any{
		"challenge": login(), "method": "recovery", "code": codes[0],
	})
	if reuse.Code != http.StatusForbidden {
		t.Fatalf("reused recovery code: got %d want 403", reuse.Code)
	}
}

// With MFA required and no factors enrolled, the user is sent to enrollment
// instead of being handed a session or locked out.
func TestLoginRequiresEnrollmentWhenMFAIsMandatory(t *testing.T) {
	h, _, _ := mfaTestHandlers(t, true)

	w := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
		"username": "admin", "password": "s3cr3t-password",
	})
	var resp MFAChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.MFAEnrollmentRequired || resp.Challenge == "" {
		t.Fatalf("expected an enrollment challenge, got %+v", resp)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("no session may be issued before enrollment completes")
	}

	begin := postJSON(t, h.LoginMFAEnrollBeginHandler, "/api/v1/login/mfa/enroll/begin", map[string]any{
		"challenge": resp.Challenge,
	})
	if begin.Code != http.StatusOK {
		t.Fatalf("enroll begin: got %d want 200 (%s)", begin.Code, begin.Body.String())
	}
	var secretResp MFAEnrollBeginResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &secretResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wrong := postJSON(t, h.LoginMFAEnrollFinishHandler, "/api/v1/login/mfa/enroll/finish", map[string]any{
		"challenge": resp.Challenge, "code": "000000",
	})
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong enrollment code: got %d want 403", wrong.Code)
	}

	code, err := mfa.Code(secretResp.Secret, mfa.Step(time.Now()))
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	finish := postJSON(t, h.LoginMFAEnrollFinishHandler, "/api/v1/login/mfa/enroll/finish", map[string]any{
		"challenge": resp.Challenge, "code": code,
	})
	if finish.Code != http.StatusOK {
		t.Fatalf("enroll finish: got %d want 200 (%s)", finish.Code, finish.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(finish.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session["token"] == "" {
		t.Fatalf("enrollment should end with a session: %v", session)
	}
	if codes, ok := session["recovery_codes"].([]any); !ok || len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("expected %d recovery codes, got %v", mfa.RecoveryCodeCount, session["recovery_codes"])
	}
	// The factor now exists, so the next login asks for it.
	if !h.MFA.Enabled("admin") {
		t.Fatalf("expected the user to be enrolled after finishing")
	}
}

// A user with no factors logs in as before when MFA is not required.
func TestLoginWithoutMFAIsUnchanged(t *testing.T) {
	h, _, _ := mfaTestHandlers(t, false)

	w := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
		"username": "admin", "password": "s3cr3t-password",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (%s)", w.Code, w.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session["token"] == nil || session["token"] == "" {
		t.Fatalf("expected a token for a user without MFA: %v", session)
	}
}

// Service accounts authenticate with a token; requiring interactive enrollment
// from them would break automation.
func TestServiceAccountsSkipMFAEnforcement(t *testing.T) {
	h, _, userManager := mfaTestHandlers(t, true)
	newTestUser(t, userManager, "robot", true)

	w := postJSON(t, h.LoginHandler, "/api/v1/login", map[string]any{
		"username": "robot", "password": "s3cr3t-password",
	})
	var session map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session["token"] == nil || session["token"] == "" {
		t.Fatalf("service account should log in without MFA: %v", session)
	}
}
