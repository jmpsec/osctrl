package apiclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// envURL is APIPath/environments/<parts...>, each part one escaped segment.
func (api *OsctrlAPI) envURL(parts ...string) string {
	segs := []string{APIPath, APIEnvironments}
	for _, p := range parts {
		segs = append(segs, url.PathEscape(p))
	}
	return fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(segs...))
}

// envReq sends body as JSON with method to reqURL and returns the response body.
func (api *OsctrlAPI) envReq(method, reqURL string, body interface{}) ([]byte, error) {
	var data io.Reader
	if body != nil {
		jsonMessage, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling data - %w", err)
		}
		data = bytes.NewReader(jsonMessage)
	}
	raw, err := api.ReqGeneric(method, reqURL, data)
	if err != nil {
		return raw, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return raw, nil
}

// CreateEnvironment creates an environment (global admin) and returns it
func (api *OsctrlAPI) CreateEnvironment(req types.EnvCreateRequest) (environments.TLSEnvironment, error) {
	var env environments.TLSEnvironment
	raw, err := api.envReq(http.MethodPost, api.envURL(), req)
	if err != nil {
		return env, err
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, fmt.Errorf("can not parse body - %w", err)
	}
	return env, nil
}

// PatchEnvironment updates the non-nil fields of req (global admin)
func (api *OsctrlAPI) PatchEnvironment(env string, req types.EnvUpdateRequest) error {
	_, err := api.envReq(http.MethodPatch, api.envURL(env), req)
	return err
}

// PatchEnvironmentIntervals updates the non-nil intervals, in seconds (environment admin)
func (api *OsctrlAPI) PatchEnvironmentIntervals(env string, config, log, query *int) error {
	req := types.EnvIntervalsPatchRequest{ConfigInterval: config, LogInterval: log, QueryInterval: query}
	_, err := api.envReq(http.MethodPatch, api.envURL("intervals", env), req)
	return err
}

// SetEnrollPackageURL sets an enroll package URL; action is set_deb, set_rpm,
// set_msi or set_pkg (environment admin)
func (api *OsctrlAPI) SetEnrollPackageURL(env, action, pkgURL string) error {
	var req types.ApiActionsRequest
	switch action {
	case settings.SetDebPackage:
		req.DebPkgURL = pkgURL
	case settings.SetRpmPackage:
		req.RpmPkgURL = pkgURL
	case settings.SetMsiPackage:
		req.MsiPkgURL = pkgURL
	case settings.SetMacPackage:
		req.MacPkgURL = pkgURL
	default:
		return fmt.Errorf("unknown package action %q", action)
	}
	_, err := api.envReq(http.MethodPost, api.envURL(env, "enroll", action), req)
	return err
}

// UploadCertificate sets the enroll certificate (PEM) of an environment (environment admin)
func (api *OsctrlAPI) UploadCertificate(env, certPEM string) error {
	req := map[string]string{"certificate_b64": base64.StdEncoding.EncodeToString([]byte(certPEM))}
	_, err := api.envReq(http.MethodPost, api.envURL(env, "enroll", "cert"), req)
	return err
}

// DeleteEnvironment deletes an environment (global admin)
func (api *OsctrlAPI) DeleteEnvironment(env string) error {
	_, err := api.envReq(http.MethodDelete, api.envURL(env), nil)
	return err
}
