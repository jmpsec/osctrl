package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// UserHandler - GET Handler for environment users
func (h *HandlersApi) UserHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract username
	usernameVar := r.PathValue("username")
	if usernameVar == "" {
		apiErrorResponse(w, "error with username", http.StatusBadRequest, nil)
		return
	}
	// Get user
	user, err := h.Users.Get(usernameVar)
	if err != nil {
		apiErrorResponse(w, "error getting user", http.StatusInternalServerError, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned user %s", usernameVar)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, user)
}

// UsersHandler - GET Handler for multiple JSON nodes
func (h *HandlersApi) UsersHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get users
	users, err := h.Users.All()
	if err != nil {
		apiErrorResponse(w, "error getting users", http.StatusInternalServerError, err)
		return
	}
	if len(users) == 0 {
		apiErrorResponse(w, "no users", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned %d users", len(users))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, users)
}

// UserActionHandler - POST Handler to take actions on a user by username and environment
func (h *HandlersApi) UserActionHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract username
	usernameVar := r.PathValue("username")
	if usernameVar == "" {
		apiErrorResponse(w, "error with username", http.StatusBadRequest, nil)
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var u types.ApiUserRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Verification for username
	if u.Username == "" || u.Username != usernameVar {
		apiErrorResponse(w, "error with username", http.StatusBadRequest, fmt.Errorf("username in body does not match URL"))
		return
	}
	var returnData string
	switch actionVar {
	case users.ActionAdd:
		if h.Users.Exists(u.Username) {
			apiErrorResponse(w, "error adding user", http.StatusInternalServerError, fmt.Errorf("user %s already exists", u.Username))
			return
		}
		// Prepare user to create
		newUser, err := h.Users.New(u.Username, u.Password, u.Email, u.Fullname, u.Admin, u.Service)
		if err != nil {
			apiErrorResponse(w, "error with new user", http.StatusInternalServerError, err)
			return
		}
		// Create new user
		if err = h.Users.Create(newUser); err != nil {
			apiErrorResponse(w, "error creating user", http.StatusInternalServerError, err)
			return
		}
		// If user is admin, give access to all environments
		envs := u.Environments
		if u.Admin {
			envs, err = h.Envs.UUIDs()
			if err != nil {
				apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
				return
			}
		}
		access := h.Users.GenEnvUserAccess(envs, true, (u.Admin), (u.Admin), (u.Admin))
		perms := h.Users.GenPermissions(u.Username, ctx[ctxUser], access)
		if err := h.Users.CreatePermissions(perms); err != nil {
			apiErrorResponse(w, "error creating permissions", http.StatusInternalServerError, err)
			return
		}
		returnData = "user added successfully"
	case users.ActionEdit:
		// Check if user exists
		user, err := h.Users.Get(usernameVar)
		if err != nil {
			apiErrorResponse(w, "user does not exist", http.StatusBadRequest, err)
			return
		}
		if u.Password != "" {
			if err := h.Users.ChangePassword(u.Username, u.Password); err != nil {
				apiErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Email != "" && u.Email != user.Email {
			if err := h.Users.ChangeEmail(u.Username, u.Email); err != nil {
				apiErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Fullname != "" && u.Fullname != user.Fullname {
			if err := h.Users.ChangeFullname(u.Username, u.Fullname); err != nil {
				apiErrorResponse(w, "error changing name", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Admin && !user.Admin {
			if err := h.Users.ChangeAdmin(u.Username, true); err != nil {
				apiErrorResponse(w, "error changing admin", http.StatusInternalServerError, err)
				return
			}
		} else if u.NotAdmin && user.Admin {
			if err := h.Users.ChangeAdmin(u.Username, false); err != nil {
				apiErrorResponse(w, "error changing non-admin", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Service && !user.Service {
			if err := h.Users.ChangeService(u.Username, true); err != nil {
				apiErrorResponse(w, "error changing service", http.StatusInternalServerError, err)
				return
			}
		} else if u.NotService && user.Service {
			if err := h.Users.ChangeService(u.Username, false); err != nil {
				apiErrorResponse(w, "error changing non-service", http.StatusInternalServerError, err)
				return
			}
		}
		// TODO: If user is admin, give access to all environments
		returnData = "user updated successfully"
	case users.ActionRemove:
		// Check if user exists
		if u.Username == ctx[ctxUser] {
			apiErrorResponse(w, "error removing user", http.StatusBadRequest, fmt.Errorf("user %s can not remove itself", u.Username))
			return
		}
		exist, user := h.Users.ExistsGet(u.Username)
		if exist {
			if err := h.Users.Delete(user.Username); err != nil {
				apiErrorResponse(w, "error removing user", http.StatusInternalServerError, err)
				return
			}
			// Delete permissions
			if err := h.Users.DeleteAllPermissions(user.Username); err != nil {
				apiErrorResponse(w, "error removing user permissions", http.StatusInternalServerError, err)
				return
			}
		}
		returnData = "user removed successfully"
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned [%s]", returnData)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}
