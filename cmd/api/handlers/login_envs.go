package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// LoginEnvironmentsHandler - GET /api/v1/login/environments
//
// Pre-auth endpoint that returns the list of environments the user may attempt
// to log into. Surface is intentionally minimal: only the env UUID and name.
// No enroll secrets, no certificates, no settings, no hostnames — those all
// stay behind auth on /api/v1/environments and its CRUD siblings.
//
// Rationale: forcing the user to type the env name on the login screen is bad
// UX (you don't know it until you've logged in once, and single-env installs
// only ever have one option). The legacy admin shows env names pre-auth in its
// login form, so we're not changing the security posture — just exposing the
// same identifiers that the URL space already commits to using post-auth.
//
// Like POST /login/{env}, this lives behind the per-IP rate limit registered
// in main.go so the endpoint can't be turned into an env-enumeration oracle
// for brute-force prep beyond the limit.
func (h *HandlersApi) LoginEnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envs, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "error listing environments", http.StatusInternalServerError, err)
		return
	}
	// Project to (uuid, name) only. Constructing the response explicitly
	// guards against future fields being added to TLSEnvironment that
	// shouldn't be exposed pre-auth — if someone adds e.g. a `Secret` field
	// to that struct later, this handler still ships only the two fields
	// listed here.
	out := make([]types.LoginEnvironment, 0, len(envs))
	for _, e := range envs {
		out = append(out, types.LoginEnvironment{
			UUID: e.UUID,
			Name: e.Name,
		})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}
