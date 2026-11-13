package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

// santaAuditPerHour caps failed-sync audit writes per environment, so
// unauthenticated requests cannot flood audit_logs (env UUIDs are not secret).
const santaAuditPerHour = 60

const santaTokenHeader = "X-Osctrl-Santa-Token"

// SantaHandler serves the Santa sync protocol at
// POST /{env}/santa/sync/{stage}/{machineid}.
//
// There is deliberately no IP rate limiter here: the per-environment token
// has 256 bits, so brute force is not feasible, and the enroll limiter would
// throttle whole fleets behind one NAT address. Every failure is audited
// instead. Error responses have empty bodies and never echo request data.
func (h *HandlersTLS) SantaHandler(w http.ResponseWriter, r *http.Request) {
	fail := func(code int) { utils.HTTPResponse(w, "", code, []byte("")) }
	envVar := r.PathValue("env")
	if !utils.CheckUUID(envVar) {
		fail(http.StatusBadRequest)
		return
	}
	env, known, err := h.getEnv(context.TODO(), envVar, "SantaHandler")
	if err != nil {
		fail(http.StatusInternalServerError)
		return
	}
	// An unknown environment answers like a bad token: no existence oracle.
	if !known {
		fail(http.StatusForbidden)
		return
	}
	ip := utils.GetIP(r)
	if !h.Santa.CheckToken(env.ID, r.Header.Get(santaTokenHeader)) {
		h.santaAudit(ip, env, "invalid or missing token")
		fail(http.StatusForbidden)
		return
	}
	machine := r.PathValue("machineid")
	if !utils.CheckUUID(machine) {
		fail(http.StatusBadRequest)
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(machine, env.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		h.santaAudit(ip, env, "machine is not a node of this environment")
		fail(http.StatusForbidden)
		return
	}
	if err != nil {
		log.Err(err).Msg("santa: error getting node")
		fail(http.StatusInternalServerError)
		return
	}
	nodeTags, err := h.Tags.GetTagsByNodeIDs([]uint{node.ID})
	if err != nil {
		log.Err(err).Msg("santa: error getting node tags")
		fail(http.StatusInternalServerError)
		return
	}
	sn := santa.SyncNode{EnvID: env.ID, NodeID: node.ID, UUID: node.UUID}
	for _, t := range nodeTags[node.ID] {
		sn.Tags = append(sn.Tags, t.Name)
	}
	r.Body = http.MaxBytesReader(w, r.Body, santa.MaxRawBody)
	switch r.PathValue("stage") {
	case "preflight":
		err = santaStage(w, r, &syncv1.PreflightRequest{}, func(q *syncv1.PreflightRequest) (proto.Message, error) {
			return h.Santa.Preflight(sn, q)
		})
	case "eventupload":
		err = santaStage(w, r, &syncv1.EventUploadRequest{}, func(q *syncv1.EventUploadRequest) (proto.Message, error) {
			evs, err := h.Santa.StoreEvents(sn, q)
			if err != nil {
				return nil, err
			}
			h.santaForward(env, node.UUID, evs)
			return &syncv1.EventUploadResponse{}, nil
		})
	case "ruledownload":
		err = santaStage(w, r, &syncv1.RuleDownloadRequest{}, func(q *syncv1.RuleDownloadRequest) (proto.Message, error) {
			return h.Santa.RuleDownload(sn, q)
		})
	case "postflight":
		err = santaStage(w, r, &syncv1.PostflightRequest{}, func(q *syncv1.PostflightRequest) (proto.Message, error) {
			return h.Santa.Postflight(sn, q)
		})
	default:
		fail(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Err(err).Str("stage", r.PathValue("stage")).Msg("santa: sync error")
		fail(santaErrorStatus(err))
	}
}

// santaForward hands stored events to the alert rules and the log sinks. The
// events are already stored, so a sink failure is logged and the upload still
// succeeds: failing it would make Santa send the batch again and store it twice.
func (h *HandlersTLS) santaForward(env environments.TLSEnvironment, uuid string, evs []santa.Event) {
	if h.Logs == nil || len(evs) == 0 {
		return
	}
	if h.Logs.Alerts != nil {
		fields := make([]map[string]string, len(evs))
		for i := range evs {
			fields[i] = evs[i].AlertFields()
		}
		h.Logs.Alerts.MatchSantaEvents(env.ID, env.Name, uuid, fields)
	}
	// A JSON array, like osquery log batches: several sinks require one.
	data, err := json.Marshal(evs)
	if err != nil {
		log.Err(err).Msg("santa: error encoding events for log sinks")
		return
	}
	if err := h.Logs.LogWithEnv(types.SantaLog, data, env.ID, env.Name, uuid, false); err != nil {
		log.Err(err).Msg("santa: error sending events to log sinks")
	}
}

// santaAudit writes a failed-sync audit entry unless the environment's audit
// cap is spent, in which case the drop is counted.
func (h *HandlersTLS) santaAudit(ip string, env environments.TLSEnvironment, reason string) {
	if h.santaAuditCap != nil && !h.santaAuditCap.Allow(strings.ToLower(env.UUID)) {
		santaAuthAuditDropped.WithLabelValues(env.Name).Inc()
		return
	}
	h.AuditLog.FailedSanta(ip, env.Name, reason, env.ID)
}

// santaStage decodes the request, runs the stage and encodes the response in
// the request's encoding. A non-nil error means nothing was written.
func santaStage[Q proto.Message](w http.ResponseWriter, r *http.Request, req Q, call func(Q) (proto.Message, error)) error {
	enc, err := santa.Decode(r, req)
	if err != nil {
		return fmt.Errorf("%w: %w", errSantaBadRequest, err)
	}
	resp, err := call(req)
	if err != nil {
		return err
	}
	return santa.Encode(w, enc, resp)
}

// santaErrorStatus maps stage errors to statuses; size limits win over the
// generic decode failure they are wrapped in.
func santaErrorStatus(err error) int {
	switch {
	case errors.Is(err, santa.ErrTooLarge), isMaxBytesError(err):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, santa.ErrRulesChanged):
		return http.StatusConflict
	case errors.Is(err, santa.ErrNoPreflight):
		return http.StatusBadRequest
	case errors.Is(err, errSantaBadRequest):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

var errSantaBadRequest = errors.New("santa: bad request")
