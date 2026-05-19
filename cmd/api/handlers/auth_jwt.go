package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/users"
)

// userJWTSessionTokens issues the osctrl_token and osctrl_csrf cookies
// for an already-authenticated user. Encapsulates the cookie-issuance
// dance shared between LoginHandler (password flow) and the federated
// auth callbacks.
//
// On success: both cookies are set on w. On failure: an apiErrorResponse
// is written and the function returns a non-nil error so the caller
// can early-return without writing anything else.
//
// The function:
//
//  1. Decides whether to mint a fresh JWT or reuse the user's stored
//     APIToken (the same freshness logic as LoginHandler — re-issue
//     when no token, expired, or within 60s of expiry).
//  2. Generates a 16-byte CSRF token (32 hex chars).
//  3. Persists token + CSRF + last-ip + user-agent via
//     UpdateMetadata / UpdateToken.
//  4. Sets osctrl_token (HttpOnly, Secure, SameSite=Lax) and
//     osctrl_csrf (NOT HttpOnly — SPA must read it).
//
// expHours: see users.CreateToken's expHours parameter. 0 means
// "use JWTConfig.HoursToExpire."
func (h *HandlersApi) userJWTSessionTokens(w http.ResponseWriter, user users.AdminUser, expHours int, clientIP, userAgent string) (users.AdminUser, error) {
	now := time.Now()
	const freshnessWindow = 60 * time.Second
	var tokenExp time.Time
	needsRefresh := user.APIToken == "" || user.TokenExpire.Before(now.Add(freshnessWindow))
	if needsRefresh {
		token, exp, err := h.Users.CreateToken(user.Username, h.ServiceName, expHours)
		if err != nil {
			apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
			return user, err
		}
		if err := h.Users.UpdateToken(user.Username, token, exp); err != nil {
			apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
			return user, err
		}
		user.APIToken = token
		tokenExp = exp
	} else {
		tokenExp = user.TokenExpire
	}

	// Fresh CSRF on every login (defense in depth — even if an
	// attacker stole the previous CSRF cookie, the next login
	// rotates it).
	csrfBytes := make([]byte, 16)
	if _, err := rand.Read(csrfBytes); err != nil {
		apiErrorResponse(w, "error generating csrf token", http.StatusInternalServerError, err)
		return user, err
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	if err := h.Users.UpdateMetadata(clientIP, userAgent, user.Username, csrfToken); err != nil {
		apiErrorResponse(w, "error persisting csrf token", http.StatusInternalServerError, err)
		return user, err
	}

	maxAge := int(time.Until(tokenExp).Seconds())
	if maxAge <= 0 {
		err := fmt.Errorf("token expiry in past or zero: %v", tokenExp)
		apiErrorResponse(w, "token already expired", http.StatusInternalServerError, err)
		return user, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_token",
		Value:    user.APIToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "osctrl_csrf",
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return user, nil
}
