package handlers

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const maxBodyOsquery = 4 << 10 // 4 KiB: osctrld osquery version request

// osqueryToken is the shape of platform, arch and format: short and plain.
var osqueryToken = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)

// OsqueryHandler tells osctrld which osquery version a node of the
// environment should run. Anything that is malformed or not such a node gets
// 400, never 404: osctrld reads 404 as "route not served". A well-formed but
// unsupported platform is a 200 with a reason.
func (h *HandlersTLS) OsqueryHandler(w http.ResponseWriter, r *http.Request) {
	var t types.OsctrldOsqueryRequest
	env, ok := h.osctrldRequest(w, r, maxBodyOsquery, &t, func() string { return t.Secret })
	if !ok {
		return
	}
	if !utils.CheckUUID(t.UUID) || !osqueryToken.MatchString(t.Platform) || !osqueryToken.MatchString(t.Arch) ||
		!osqueryToken.MatchString(t.Format) || (t.InstalledVersion != "" && !osqueryversions.ValidVersion(t.InstalledVersion)) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(t.UUID, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
			return
		}
		log.Err(err).Msgf("%s environment: error looking up node for osctrld osquery request", env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	res, err := h.OsqueryVersions.Resolve(osqueryversions.ResolveInput{
		EnvironmentID: env.ID, NodeUUID: node.UUID, Platform: t.Platform, Arch: t.Arch,
		Format: t.Format, InstalledVersion: t.InstalledVersion,
	}, time.Now())
	if err != nil {
		log.Err(err).Msgf("%s environment: error resolving osquery version", env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	out := types.OsctrldOsqueryResponse{
		Reason: res.Reason, Source: res.Source, RequestID: res.RequestID, ReportedVersion: node.OsqueryVersion,
	}
	if res.Target != nil && res.Previous != nil {
		out.Target = &types.OsctrldOsqueryRef{Version: res.Target.Version, SHA256: res.Target.SHA256}
		out.Previous = &types.OsctrldOsqueryRef{Version: res.Previous.Version, SHA256: res.Previous.SHA256}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}
