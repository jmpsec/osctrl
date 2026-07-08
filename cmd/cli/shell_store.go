package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// APIStatsPath is the REST path for dashboard stats.
const APIStatsPath = "/stats"

// tui_store.go — single data-access façade for the interactive TUI.
//
// The TUI never branches on dbFlag/apiFlag itself; it talks to a DataStore
// implementation. apiStore wraps the existing OsctrlAPI client; dbStore wraps
// the pkg/* managers. DTOs (xxxRow) decouple the views from the underlying
// model JSON shapes so a view does not care whether data came from REST or GORM.

// ─────────────────────────────── DTOs ───────────────────────────────

type tuiPlatformCounts struct {
	Linux   int64 `json:"linux"`
	Darwin  int64 `json:"darwin"`
	Windows int64 `json:"windows"`
	Other   int64 `json:"other"`
}

type tuiEnvStats struct {
	UUID          string            `json:"uuid"`
	Name          string            `json:"name"`
	Active        int64             `json:"active"`
	Inactive      int64             `json:"inactive"`
	Total         int64             `json:"total"`
	ActiveQueries int               `json:"active_queries"`
	ActiveCarves  int               `json:"active_carves"`
	Platforms     tuiPlatformCounts `json:"platform_counts"`
}

type tuiStats struct {
	TotalNodes         int64             `json:"total_nodes"`
	ActiveNodes        int64             `json:"active_nodes"`
	InactiveNodes      int64             `json:"inactive_nodes"`
	InactiveHours      int64             `json:"inactive_hours"`
	TotalActiveQueries int               `json:"total_active_queries"`
	TotalActiveCarves  int               `json:"total_active_carves"`
	Platforms          tuiPlatformCounts `json:"platform_counts"`
	Environments       []tuiEnvStats     `json:"environments"`
}

type envRow struct {
	Name         string
	UUID         string
	Hostname     string
	Type         string
	Icon         string
	DebugHTTP    bool
	EnrollExpire time.Time
	RemoveExpire time.Time
	AcceptEnroll bool
	CreatedAt    time.Time
}

type nodeRow struct {
	UUID            string
	Hostname        string
	Localname       string
	Platform        string
	PlatformVersion string
	OsqueryVersion  string
	IPAddress       string
	Username        string
	Environment     string
	LastSeen        string
	FirstSeen       string
	Active          bool
	CPU             string
	Memory          string
	HardwareSerial  string
	BytesReceived   int
	Raw             nodes.OsqueryNode // kept for detail rendering (json:"-")
}

type queryRow struct {
	Name       string
	Creator    string
	Query      string
	Type       string
	Expected   int
	Executions int
	Errors     int
	Status     string
	Hidden     bool
	Created    string
	Expiration string
	Target     string
}

type carveRow struct {
	CarveID         string
	QueryName       string
	UUID            string
	Environment     string
	Path            string
	Status          string
	CarveSize       int
	CompletedBlocks int
	TotalBlocks     int
	CompletedAt     string
}

type tagRow struct {
	Name        string
	Description string
	Color       string
	Icon        string
	CreatedBy   string
	TagType     string
	CustomTag   string
	AutoTag     bool
}

type userRow struct {
	Username   string
	Email      string
	Fullname   string
	Admin      bool
	Service    bool
	LastAccess string
}

type auditRow struct {
	When     string
	Username string
	Service  string
	Line     string
	LogType  string
	Severity string
	SourceIP string
}

type settingRow struct {
	Name    string
	Service string
	Type    string
	Value   string
	Info    string
}

type permRow struct {
	Username    string
	Environment string
	AccessType  string
	AccessValue bool
	GrantedBy   string
}

// runQueryReq captures the shared shape of "run query" and "run carve" forms.
type runQueryReq struct {
	Env       string
	Query     string
	UUIDs     []string
	Hosts     []string
	Platforms []string
	Tags      []string
	Hidden    bool
	ExpHours  int
}

// ─────────────────────────────── Interface ───────────────────────────────

type DataStore interface {
	Mode() string // "api" or "db"
	Stats() (tuiStats, error)
	Environments() ([]envRow, error)
	EnvNames() ([]string, error)
	Nodes(env, target string) ([]nodeRow, error)
	Node(env, identifier string) (nodeRow, error)
	Queries(env, target string) ([]queryRow, error)
	QueryResults(env, name string) (string, error)
	Carves(env string) ([]carveRow, error)
	CarveQueries(env, target string) ([]queryRow, error)
	Tags() ([]tagRow, error)
	Users() ([]userRow, error)
	AuditLogs() ([]auditRow, error)
	Settings() ([]settingRow, error)

	DeleteNode(env, identifier string) error
	RunQuery(req runQueryReq) error
	CompleteQuery(env, name string) error
	ExpireQuery(env, name string) error
	DeleteQuery(env, name string) error
	RunCarve(req runQueryReq) error
	CompleteCarve(env, name string) error
	ExpireCarve(env, name string) error
	DeleteCarve(env, name string) error

	// Management actions
	TagNode(env, uuid, tag string) error
	AddTag(env, name, color, icon, desc, tagType, custom string) error
	EditTag(env, name, color, icon, desc, tagType, custom string) error
	DeleteTag(env, name string) error
	CreateUser(username, password, email, fullname string, admin, service bool) error
	EditUserField(username, field, value string) error
	DeleteUser(username string) error
	EnvAction(name, target, action string) (string, error)
	AddSetting(service, name, typ, value string) error
	UpdateSetting(service, name, typ, value string) error
	DeleteSetting(service, name string) error
	Permissions(username string) ([]permRow, error)
}

// ─────────────────────────────── helpers ───────────────────────────────

func isActive(lastSeen time.Time, hours int64) bool {
	if hours <= 0 {
		hours = 24
	}
	return time.Since(lastSeen) < time.Duration(hours)*time.Hour
}

func queryStatus(q queries.DistributedQuery) string {
	switch {
	case q.Deleted:
		return "DELETED"
	case q.Expired:
		return "EXPIRED"
	case q.Completed:
		return "COMPLETE"
	case q.Active:
		return "ACTIVE"
	default:
		return "—"
	}
}

func csvSplit(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func tagTypeName(t uint) string {
	switch t {
	case tags.TagTypeEnv:
		return "env"
	case tags.TagTypePlatform:
		return "platform"
	case tags.TagTypeCustom:
		return "custom"
	case tags.TagTypeUnknown:
		return "unknown"
	case tags.TagTypeTag:
		return "tag"
	default:
		return strconv.FormatUint(uint64(t), 10)
	}
}

// parseTagType maps a friendly tag-type name to its numeric constant.
func parseTagType(s string) uint {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "env", "environment":
		return tags.TagTypeEnv
	case "platform":
		return tags.TagTypePlatform
	case "custom":
		return tags.TagTypeCustom
	case "tag":
		return tags.TagTypeTag
	case "unknown":
		return tags.TagTypeUnknown
	default:
		return tags.TagTypeCustom
	}
}

func auditTypeName(t uint) string {
	switch t {
	case auditlog.LogTypeLogin:
		return "login"
	case auditlog.LogTypeNode:
		return "node"
	case auditlog.LogTypeLogout:
		return "logout"
	case auditlog.LogTypeTag:
		return "tag"
	case auditlog.LogTypeSetting:
		return "setting"
	case auditlog.LogTypeVisit:
		return "visit"
	case auditlog.LogTypeUser:
		return "user"
	case auditlog.LogTypeQuery:
		return "query"
	case auditlog.LogTypeCarve:
		return "carve"
	case auditlog.LogTypeEnvironment:
		return "env"
	default:
		return strconv.FormatUint(uint64(t), 10)
	}
}

func settingValueDisplay(s settings.SettingValue) string {
	switch s.Type {
	case settings.TypeBoolean:
		return strconv.FormatBool(s.Boolean)
	case settings.TypeInteger:
		return strconv.FormatInt(s.Integer, 10)
	default:
		return s.String
	}
}

// nodeToRow maps an OsqueryNode plus inactive threshold to a nodeRow.
func nodeToRow(n nodes.OsqueryNode, hours int64) nodeRow {
	return nodeRow{
		UUID:            n.UUID,
		Hostname:        n.Hostname,
		Localname:       n.Localname,
		Platform:        n.Platform,
		PlatformVersion: n.PlatformVersion,
		OsqueryVersion:  n.OsqueryVersion,
		IPAddress:       n.IPAddress,
		Username:        n.Username,
		Environment:     n.Environment,
		LastSeen:        utils.PastFutureTimes(n.LastSeen),
		FirstSeen:       utils.PastFutureTimes(n.CreatedAt),
		Active:          isActive(n.LastSeen, hours),
		CPU:             n.CPU,
		Memory:          n.Memory,
		HardwareSerial:  n.HardwareSerial,
		BytesReceived:   n.BytesReceived,
		Raw:             n,
	}
}

func queryToRow(q queries.DistributedQuery) queryRow {
	return queryRow{
		Name:       q.Name,
		Creator:    q.Creator,
		Query:      q.Query,
		Type:       q.Type,
		Expected:   q.Expected,
		Executions: q.Executions,
		Errors:     q.Errors,
		Status:     queryStatus(q),
		Hidden:     q.Hidden,
		Created:    utils.PastFutureTimes(q.CreatedAt),
		Expiration: utils.PastFutureTimes(q.Expiration),
		Target:     q.Target,
	}
}

func carveToRow(c carves.CarvedFile) carveRow {
	completed := "—"
	if !c.CompletedAt.IsZero() {
		completed = utils.PastFutureTimes(c.CompletedAt)
	}
	return carveRow{
		CarveID:         c.CarveID,
		QueryName:       c.QueryName,
		UUID:            c.UUID,
		Environment:     c.Environment,
		Path:            c.Path,
		Status:          c.Status,
		CarveSize:       c.CarveSize,
		CompletedBlocks: c.CompletedBlocks,
		TotalBlocks:     c.TotalBlocks,
		CompletedAt:     completed,
	}
}

func envToRow(e environments.TLSEnvironment) envRow {
	return envRow{
		Name:         e.Name,
		UUID:         e.UUID,
		Hostname:     e.Hostname,
		Type:         e.Type,
		Icon:         e.Icon,
		DebugHTTP:    e.DebugHTTP,
		EnrollExpire: e.EnrollExpire,
		RemoveExpire: e.RemoveExpire,
		AcceptEnroll: e.AcceptEnrolls,
		CreatedAt:    e.CreatedAt,
	}
}

func tagToRow(t tags.AdminTag) tagRow {
	return tagRow{
		Name:        t.Name,
		Description: t.Description,
		Color:       t.Color,
		Icon:        t.Icon,
		CreatedBy:   t.CreatedBy,
		TagType:     tagTypeName(t.TagType),
		CustomTag:   t.CustomTag,
		AutoTag:     t.AutoTag,
	}
}

func userToRow(u users.AdminUser) userRow {
	last := "—"
	if !u.LastAccess.IsZero() {
		last = utils.PastFutureTimes(u.LastAccess)
	}
	return userRow{Username: u.Username, Email: u.Email, Fullname: u.Fullname, Admin: u.Admin, Service: u.Service, LastAccess: last}
}

func auditToRow(a auditlog.AuditLog) auditRow {
	return auditRow{
		When:     utils.PastFutureTimes(a.CreatedAt),
		Username: a.Username,
		Service:  a.Service,
		Line:     a.Line,
		LogType:  auditTypeName(a.LogType),
		Severity: strconv.FormatUint(uint64(a.Severity), 10),
		SourceIP: a.SourceIP,
	}
}

// ─────────────────────────────── apiStore ───────────────────────────────

type apiStore struct {
	api *OsctrlAPI
}

func newAPIStore(api *OsctrlAPI) DataStore { return &apiStore{api: api} }

func (s *apiStore) Mode() string { return "api" }

func (s *apiStore) Stats() (tuiStats, error) {
	var st tuiStats
	reqURL := fmt.Sprintf("%s%s", s.api.Configuration.URL, path.Join(APIPath, APIStatsPath))
	raw, err := s.api.GetGeneric(reqURL, nil)
	if err != nil {
		return st, fmt.Errorf("stats: %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, fmt.Errorf("stats parse: %w", err)
	}
	return st, nil
}

func (s *apiStore) Environments() ([]envRow, error) {
	envs, err := s.api.GetEnvironments()
	if err != nil {
		return nil, err
	}
	out := make([]envRow, 0, len(envs))
	for _, e := range envs {
		out = append(out, envToRow(e))
	}
	return out, nil
}

func (s *apiStore) EnvNames() ([]string, error) {
	envs, err := s.Environments()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(envs))
	for _, e := range envs {
		out = append(out, e.Name)
	}
	return out, nil
}

func (s *apiStore) Nodes(env, target string) ([]nodeRow, error) {
	nds, err := s.api.GetNodes(env, target)
	if err != nil {
		return nil, err
	}
	out := make([]nodeRow, 0, len(nds))
	for _, n := range nds {
		out = append(out, nodeToRow(n, 24))
	}
	return out, nil
}

func (s *apiStore) Node(env, identifier string) (nodeRow, error) {
	n, err := s.api.GetNode(env, identifier)
	if err != nil {
		return nodeRow{}, err
	}
	return nodeToRow(n, 24), nil
}

func (s *apiStore) Queries(env, target string) ([]queryRow, error) {
	qs, err := s.api.GetQueries(target, env)
	if err != nil {
		return nil, err
	}
	out := make([]queryRow, 0, len(qs))
	for _, q := range qs {
		out = append(out, queryToRow(q))
	}
	return out, nil
}

func (s *apiStore) QueryResults(env, name string) (string, error) {
	reqURL := fmt.Sprintf("%s%s", s.api.Configuration.URL, path.Join(APIPath, APIQueries, env, "results", name))
	raw, err := s.api.GetGeneric(reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("results: %w - %s", err, string(raw))
	}
	// Pretty-print if it's JSON, otherwise return raw.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err == nil && pretty.Len() > 0 {
		return pretty.String(), nil
	}
	return string(raw), nil
}

func (s *apiStore) Carves(env string) ([]carveRow, error) {
	cs, err := s.api.GetCarves(env)
	if err != nil {
		return nil, err
	}
	out := make([]carveRow, 0, len(cs))
	for _, c := range cs {
		out = append(out, carveToRow(c))
	}
	return out, nil
}

func (s *apiStore) CarveQueries(env, target string) ([]queryRow, error) {
	qs, err := s.api.GetCarveQueries(target, env)
	if err != nil {
		return nil, err
	}
	out := make([]queryRow, 0, len(qs))
	for _, q := range qs {
		out = append(out, queryToRow(q))
	}
	return out, nil
}

func (s *apiStore) Tags() ([]tagRow, error) {
	ts, err := s.api.GetAllTags()
	if err != nil {
		return nil, err
	}
	out := make([]tagRow, 0, len(ts))
	for _, t := range ts {
		out = append(out, tagToRow(t))
	}
	return out, nil
}

func (s *apiStore) Users() ([]userRow, error) {
	us, err := s.api.GetUsers()
	if err != nil {
		return nil, err
	}
	out := make([]userRow, 0, len(us))
	for _, u := range us {
		out = append(out, userToRow(u))
	}
	return out, nil
}

func (s *apiStore) AuditLogs() ([]auditRow, error) {
	ls, err := s.api.GetAuditLogs()
	if err != nil {
		return nil, err
	}
	out := make([]auditRow, 0, len(ls))
	for _, a := range ls {
		out = append(out, auditToRow(a))
	}
	return out, nil
}

func (s *apiStore) Settings() ([]settingRow, error) {
	return nil, fmt.Errorf("settings are not exposed by the REST API; use --db mode")
}

func (s *apiStore) DeleteNode(env, id string) error { return s.api.DeleteNode(env, id) }

func (s *apiStore) RunQuery(req runQueryReq) error {
	_, err := s.api.RunQuery(req.Env, req.Query, req.UUIDs, req.Hosts, req.Platforms, req.Tags, req.Hidden, req.ExpHours)
	return err
}

func (s *apiStore) CompleteQuery(env, name string) error {
	_, err := s.api.CompleteQuery(env, name)
	return err
}
func (s *apiStore) ExpireQuery(env, name string) error {
	_, err := s.api.ExpireQuery(env, name)
	return err
}
func (s *apiStore) DeleteQuery(env, name string) error {
	_, err := s.api.DeleteQuery(env, name)
	return err
}

func (s *apiStore) RunCarve(req runQueryReq) error {
	_, err := s.api.RunCarve(req.Env, req.Query, req.UUIDs, req.Hosts, req.Platforms, req.Tags, req.Hidden, req.ExpHours)
	return err
}
func (s *apiStore) CompleteCarve(env, name string) error {
	_, err := s.api.CompleteCarve(env, name)
	return err
}
func (s *apiStore) ExpireCarve(env, name string) error {
	_, err := s.api.ExpireCarve(env, name)
	return err
}
func (s *apiStore) DeleteCarve(env, name string) error {
	_, err := s.api.DeleteCarve(env, name)
	return err
}

// ─────────────────────────────── dbStore ───────────────────────────────

type dbStore struct{}

func newDBStore() DataStore { return &dbStore{} }

func (s *dbStore) Mode() string { return "db" }

func (s *dbStore) inactiveHours() int64 {
	if settingsmgr == nil {
		return 24
	}
	h := settingsmgr.InactiveHours(settings.NoEnvironmentID)
	if h <= 0 {
		// Missing/unset inactive_hours setting — default to a sane 24h so the
		// active/inactive filter and status column aren't degenerate.
		return 24
	}
	return h
}

func (s *dbStore) Stats() (tuiStats, error) {
	allEnvs, err := envs.All()
	if err != nil {
		return tuiStats{}, fmt.Errorf("envs: %w", err)
	}
	hours := s.inactiveHours()
	out := tuiStats{InactiveHours: hours, Environments: make([]tuiEnvStats, 0, len(allEnvs))}
	for _, e := range allEnvs {
		ns, err := nodesmgr.GetStatsByEnv(e.Name, hours)
		if err != nil {
			continue
		}
		pc, _ := nodesmgr.GetPlatformCountsByEnv(e.Name)
		activeQ, _ := queriesmgr.GetQueries(queries.TargetActive, e.ID)
		aq, ac := 0, 0
		for _, q := range activeQ {
			if q.Type == queries.CarveQueryType {
				ac++
			} else {
				aq++
			}
		}
		row := tuiEnvStats{
			UUID: e.UUID, Name: e.Name,
			Active: ns.Active, Inactive: ns.Inactive, Total: ns.Total,
			ActiveQueries: aq, ActiveCarves: ac,
			Platforms: tuiPlatformCounts{Linux: pc.Linux, Darwin: pc.Darwin, Windows: pc.Windows, Other: pc.Other},
		}
		out.Environments = append(out.Environments, row)
		out.TotalNodes += ns.Total
		out.ActiveNodes += ns.Active
		out.InactiveNodes += ns.Inactive
		out.TotalActiveQueries += aq
		out.TotalActiveCarves += ac
		out.Platforms.Linux += pc.Linux
		out.Platforms.Darwin += pc.Darwin
		out.Platforms.Windows += pc.Windows
		out.Platforms.Other += pc.Other
	}
	return out, nil
}

func (s *dbStore) Environments() ([]envRow, error) {
	es, err := envs.All()
	if err != nil {
		return nil, err
	}
	out := make([]envRow, 0, len(es))
	for _, e := range es {
		out = append(out, envToRow(e))
	}
	return out, nil
}

func (s *dbStore) EnvNames() ([]string, error) {
	es, err := envs.Names()
	if err != nil {
		return nil, err
	}
	return es, nil
}

func (s *dbStore) Nodes(env, target string) ([]nodeRow, error) {
	nds, err := nodesmgr.GetByEnv(env, target, s.inactiveHours())
	if err != nil {
		return nil, err
	}
	out := make([]nodeRow, 0, len(nds))
	hours := s.inactiveHours()
	for _, n := range nds {
		out = append(out, nodeToRow(n, hours))
	}
	return out, nil
}

func (s *dbStore) Node(env, identifier string) (nodeRow, error) {
	e, err := envs.Get(env)
	if err != nil {
		// fall back to name lookup
		e, err = envs.GetByName(env)
		if err != nil {
			return nodeRow{}, fmt.Errorf("env: %w", err)
		}
	}
	n, err := nodesmgr.GetByIdentifierEnv(identifier, e.ID)
	if err != nil {
		return nodeRow{}, err
	}
	return nodeToRow(n, s.inactiveHours()), nil
}

func (s *dbStore) Queries(env, target string) ([]queryRow, error) {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return nil, fmt.Errorf("env: %w", err)
		}
	}
	qs, err := queriesmgr.GetQueries(target, e.ID)
	if err != nil {
		return nil, err
	}
	out := make([]queryRow, 0, len(qs))
	for _, q := range qs {
		out = append(out, queryToRow(q))
	}
	return out, nil
}

func (s *dbStore) QueryResults(env, name string) (string, error) {
	// DB-mode results are not trivially available without the logging layer
	// wiring; surface a clear message rather than faking it.
	return "", fmt.Errorf("query results in --db mode require the logging sink; use --api mode")
}

func (s *dbStore) Carves(env string) ([]carveRow, error) {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return nil, fmt.Errorf("env: %w", err)
		}
	}
	cs, err := filecarves.GetByEnv(e.ID)
	if err != nil {
		return nil, err
	}
	out := make([]carveRow, 0, len(cs))
	for _, c := range cs {
		out = append(out, carveToRow(c))
	}
	return out, nil
}

func (s *dbStore) CarveQueries(env, target string) ([]queryRow, error) {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return nil, fmt.Errorf("env: %w", err)
		}
	}
	qs, err := queriesmgr.GetCarves(target, e.ID)
	if err != nil {
		return nil, err
	}
	out := make([]queryRow, 0, len(qs))
	for _, q := range qs {
		out = append(out, queryToRow(q))
	}
	return out, nil
}

func (s *dbStore) Tags() ([]tagRow, error) {
	ts, err := tagsmgr.All()
	if err != nil {
		return nil, err
	}
	out := make([]tagRow, 0, len(ts))
	for _, t := range ts {
		out = append(out, tagToRow(t))
	}
	return out, nil
}

func (s *dbStore) Users() ([]userRow, error) {
	us, err := adminUsers.All()
	if err != nil {
		return nil, err
	}
	out := make([]userRow, 0, len(us))
	for _, u := range us {
		out = append(out, userToRow(u))
	}
	return out, nil
}

func (s *dbStore) AuditLogs() ([]auditRow, error) {
	ls, err := auditlogsmgr.GetAll()
	if err != nil {
		return nil, err
	}
	out := make([]auditRow, 0, len(ls))
	for _, a := range ls {
		out = append(out, auditToRow(a))
	}
	return out, nil
}

func (s *dbStore) Settings() ([]settingRow, error) {
	vs, err := settingsmgr.RetrieveAllValues()
	if err != nil {
		return nil, err
	}
	out := make([]settingRow, 0, len(vs))
	for _, v := range vs {
		out = append(out, settingRow{Name: v.Name, Service: v.Service, Type: v.Type, Value: settingValueDisplay(v), Info: v.Info})
	}
	return out, nil
}

func (s *dbStore) DeleteNode(_, identifier string) error {
	if err := nodesmgr.ArchiveDeleteByUUID(identifier); err != nil {
		return err
	}
	auditlogsmgr.NodeAction(getShellUsername(), "delete node "+identifier, "CLI", 0)
	return nil
}

func (s *dbStore) RunQuery(req runQueryReq) error {
	_, err := runDistributedQuery(req)
	return err
}
func (s *dbStore) RunCarve(req runQueryReq) error {
	_, err := runDistributedCarve(req)
	return err
}

func (s *dbStore) CompleteQuery(env, name string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return err
		}
	}
	return queriesmgr.Complete(name, e.ID)
}
func (s *dbStore) ExpireQuery(env, name string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return err
		}
	}
	return queriesmgr.Expire(name, e.ID)
}
func (s *dbStore) DeleteQuery(env, name string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return err
		}
	}
	return queriesmgr.Delete(name, e.ID)
}

func (s *dbStore) CompleteCarve(env, name string) error { return s.CompleteQuery(env, name) }
func (s *dbStore) ExpireCarve(env, name string) error   { return s.ExpireQuery(env, name) }
func (s *dbStore) DeleteCarve(env, name string) error   { return s.DeleteQuery(env, name) }

// runDistributedQuery creates an on-demand query in --db mode, mirroring the
// `query run` subcommand's create path (pkg/handlers target resolution + node
// query rows + expected count + audit entry).
func runDistributedQuery(req runQueryReq) (types.ApiQueriesResponse, error) {
	e, err := envs.Get(req.Env)
	if err != nil {
		e, err = envs.GetByName(req.Env)
		if err != nil {
			return types.ApiQueriesResponse{}, fmt.Errorf("env: %w", err)
		}
	}
	queryName := queries.GenQueryName()
	expTime := queries.QueryExpiration(req.ExpHours)
	if req.ExpHours == 0 {
		expTime = time.Time{}
	}
	newQuery := queries.DistributedQuery{
		Query:         req.Query,
		Name:          queryName,
		Creator:       appName,
		Active:        true,
		Expiration:    expTime,
		Hidden:        req.Hidden,
		Type:          queries.StandardQueryType,
		EnvironmentID: e.ID,
	}
	if err := queriesmgr.Create(&newQuery); err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("query create: %w", err)
	}
	data := handlers.ProcessingQuery{
		Envs:          []string{},
		Platforms:     req.Platforms,
		UUIDs:         req.UUIDs,
		Hosts:         req.Hosts,
		Tags:          req.Tags,
		EnvID:         e.ID,
		InactiveHours: settingsmgr.InactiveHours(settings.NoEnvironmentID),
	}
	manager := handlers.Managers{Nodes: nodesmgr, Envs: envs, Tags: tagsmgr}
	targetNodesID, err := handlers.CreateQueryCarve(data, manager, newQuery)
	if err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("query targets: %w", err)
	}
	if len(targetNodesID) != 0 {
		if err := queriesmgr.CreateNodeQueries(targetNodesID, newQuery.ID); err != nil {
			return types.ApiQueriesResponse{}, fmt.Errorf("node queries: %w", err)
		}
	}
	if err := queriesmgr.SetExpected(queryName, len(targetNodesID), e.ID); err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("set expected: %w", err)
	}
	auditlogsmgr.NewQuery(getShellUsername(), req.Query, "CLI", e.ID)
	return types.ApiQueriesResponse{Name: queryName}, nil
}

// runDistributedCarve creates a carve query in --db mode, mirroring `carve run`.
func runDistributedCarve(req runQueryReq) (types.ApiQueriesResponse, error) {
	e, err := envs.Get(req.Env)
	if err != nil {
		e, err = envs.GetByName(req.Env)
		if err != nil {
			return types.ApiQueriesResponse{}, fmt.Errorf("env: %w", err)
		}
	}
	cName := carves.GenCarveName()
	expTime := queries.QueryExpiration(req.ExpHours)
	if req.ExpHours == 0 {
		expTime = time.Time{}
	}
	newQuery := queries.DistributedQuery{
		Query:         carves.GenCarveQuery(req.Query, false),
		Name:          cName,
		Creator:       appName,
		Active:        true,
		Expiration:    expTime,
		Hidden:        req.Hidden,
		Type:          queries.CarveQueryType,
		Path:          req.Query,
		EnvironmentID: e.ID,
	}
	if err := queriesmgr.Create(&newQuery); err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("carve create: %w", err)
	}
	data := handlers.ProcessingQuery{
		Envs:          []string{},
		Platforms:     req.Platforms,
		UUIDs:         req.UUIDs,
		Hosts:         req.Hosts,
		Tags:          req.Tags,
		EnvID:         e.ID,
		InactiveHours: settingsmgr.InactiveHours(settings.NoEnvironmentID),
	}
	manager := handlers.Managers{Nodes: nodesmgr, Envs: envs, Tags: tagsmgr}
	targetNodesID, err := handlers.CreateQueryCarve(data, manager, newQuery)
	if err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("carve targets: %w", err)
	}
	if len(targetNodesID) != 0 {
		if err := queriesmgr.CreateNodeQueries(targetNodesID, newQuery.ID); err != nil {
			return types.ApiQueriesResponse{}, fmt.Errorf("node queries: %w", err)
		}
	}
	if err := queriesmgr.SetExpected(cName, len(targetNodesID), e.ID); err != nil {
		return types.ApiQueriesResponse{}, fmt.Errorf("set expected: %w", err)
	}
	auditlogsmgr.NewCarve(getShellUsername(), req.Query, "CLI", e.ID)
	return types.ApiQueriesResponse{Name: cName}, nil
}

// ─────────────────────────────── apiStore: management actions ───────────────────────────────

func (s *apiStore) TagNode(env, uuid, tag string) error {
	return s.api.TagNode(env, uuid, tag, tags.TagTypeTag, "")
}

func (s *apiStore) AddTag(env, name, color, icon, desc, tagType, custom string) error {
	_, err := s.api.AddTag(env, name, color, icon, desc, parseTagType(tagType), custom)
	return err
}

func (s *apiStore) EditTag(env, name, color, icon, desc, tagType, custom string) error {
	_, err := s.api.EditTag(env, name, color, icon, desc, parseTagType(tagType), custom)
	return err
}

func (s *apiStore) DeleteTag(env, name string) error {
	_, err := s.api.DeleteTag(env, name)
	return err
}

func (s *apiStore) CreateUser(username, password, email, fullname string, admin, service bool) error {
	return s.api.CreateUser(username, password, email, fullname, "", admin, service)
}

func (s *apiStore) EditUserField(username, field, value string) error {
	cur, err := s.api.GetUser(username)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	// API expects a plaintext password; when not changing it, send empty and let
	// the server keep the existing hash.
	pass, email, fullname := "", cur.Email, cur.Fullname
	admin, service := cur.Admin, cur.Service
	switch strings.ToLower(field) {
	case "password":
		pass = value
	case "email":
		email = value
	case "fullname":
		fullname = value
	case "admin":
		admin = parseBool(value)
	case "service":
		service = parseBool(value)
	default:
		return fmt.Errorf("unknown field %q", field)
	}
	return s.api.EditUser(username, pass, email, fullname, "", admin, service)
}

func (s *apiStore) DeleteUser(username string) error { return s.api.DeleteUser(username) }

func (s *apiStore) EnvAction(name, target, action string) (string, error) {
	switch target {
	case "enroll":
		switch action {
		case "extend":
			return s.api.ExtendEnrollment(name)
		case "rotate":
			return s.api.RotateEnrollment(name)
		case "expire":
			return s.api.ExpireEnrollment(name)
		case "notexpire":
			return s.api.NotexpireEnrollment(name)
		}
	case "remove":
		switch action {
		case "extend":
			return s.api.ExtendRemove(name)
		case "rotate":
			return s.api.RotateRemove(name)
		case "expire":
			return s.api.ExpireRemove(name)
		case "notexpire":
			return s.api.NotexpireRemove(name)
		}
	}
	return "", fmt.Errorf("unknown action %s/%s", target, action)
}

func (s *apiStore) AddSetting(service, name, typ, value string) error {
	return fmt.Errorf("settings management is not exposed by the REST API; use --db mode")
}
func (s *apiStore) UpdateSetting(service, name, typ, value string) error {
	return fmt.Errorf("settings management is not exposed by the REST API; use --db mode")
}
func (s *apiStore) DeleteSetting(service, name string) error {
	return fmt.Errorf("settings management is not exposed by the REST API; use --db mode")
}

func (s *apiStore) Permissions(username string) ([]permRow, error) {
	return nil, fmt.Errorf("permissions read is not wired for the REST API in this version; use --db mode")
}

// ─────────────────────────────── dbStore: management actions ───────────────────────────────

func (s *dbStore) TagNode(_, uuid, tag string) error {
	// Resolve env from the node itself.
	n, err := nodesmgr.GetByUUID(uuid)
	if err != nil {
		return fmt.Errorf("node: %w", err)
	}
	return tagsmgr.NewTag(tag, "", "", tags.DefaultTagIcon, getShellUsername(), n.EnvironmentID, false, tags.TagTypeTag, "")
}

func (s *dbStore) AddTag(env, name, color, icon, desc, tagType, custom string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return fmt.Errorf("env: %w", err)
		}
	}
	_, err = tagsmgr.New(name, desc, color, icon, getShellUsername(), e.ID, false, parseTagType(tagType), custom)
	return err
}

func (s *dbStore) EditTag(env, name, color, icon, desc, tagType, custom string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return fmt.Errorf("env: %w", err)
		}
	}
	if desc != "" {
		if err := tagsmgr.ChangeGetDescription(name, desc, e.ID); err != nil {
			return err
		}
	}
	if color != "" {
		if err := tagsmgr.ChangeGetColor(name, color, e.ID); err != nil {
			return err
		}
	}
	if icon != "" {
		if err := tagsmgr.ChangeGetIcon(name, icon, e.ID); err != nil {
			return err
		}
	}
	if tagType != "" {
		if err := tagsmgr.ChangeGetTagType(name, parseTagType(tagType), e.ID); err != nil {
			return err
		}
	}
	if custom != "" {
		if err := tagsmgr.ChangeGetCustom(name, custom, e.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *dbStore) DeleteTag(env, name string) error {
	e, err := envs.Get(env)
	if err != nil {
		e, err = envs.GetByName(env)
		if err != nil {
			return fmt.Errorf("env: %w", err)
		}
	}
	return tagsmgr.DeleteGet(name, e.ID)
}

func (s *dbStore) CreateUser(username, password, email, fullname string, admin, service bool) error {
	u, err := adminUsers.New(username, password, email, fullname, admin, service)
	if err != nil {
		return err
	}
	return adminUsers.Create(u)
}

func (s *dbStore) EditUserField(username, field, value string) error {
	switch strings.ToLower(field) {
	case "password":
		return adminUsers.ChangePassword(username, value)
	case "email":
		return adminUsers.ChangeEmail(username, value)
	case "fullname":
		return adminUsers.ChangeFullname(username, value)
	case "admin":
		return adminUsers.ChangeAdmin(username, parseBool(value))
	case "service":
		return adminUsers.ChangeService(username, parseBool(value))
	default:
		return fmt.Errorf("unknown field %q", field)
	}
}

func (s *dbStore) DeleteUser(username string) error { return adminUsers.Delete(username) }

func (s *dbStore) EnvAction(name, target, action string) (string, error) {
	e, err := envs.Get(name)
	if err != nil {
		e, err = envs.GetByName(name)
		if err != nil {
			return "", fmt.Errorf("env: %w", err)
		}
	}
	var aerr error
	switch target {
	case "enroll":
		switch action {
		case "extend":
			aerr = envs.ExtendEnroll(e.UUID)
		case "rotate":
			aerr = envs.RotateEnroll(e.Name)
		case "expire":
			aerr = envs.ExpireEnroll(e.UUID)
		case "notexpire":
			aerr = envs.NotExpireEnroll(e.UUID)
		default:
			return "", fmt.Errorf("unknown action %s", action)
		}
	case "remove":
		switch action {
		case "extend":
			aerr = envs.ExtendRemove(e.UUID)
		case "rotate":
			aerr = envs.RotateRemove(e.Name)
		case "expire":
			aerr = envs.ExpireRemove(e.UUID)
		case "notexpire":
			aerr = envs.NotExpireRemove(e.UUID)
		default:
			return "", fmt.Errorf("unknown action %s", action)
		}
	default:
		return "", fmt.Errorf("unknown target %s", target)
	}
	if aerr != nil {
		return "", aerr
	}
	return fmt.Sprintf("%s %s %s", target, action, "ok"), nil
}

func (s *dbStore) AddSetting(service, name, typ, value string) error {
	switch strings.ToLower(typ) {
	case "string":
		return settingsmgr.NewStringValue(service, name, value, settings.NoEnvironmentID)
	case "boolean", "bool":
		return settingsmgr.NewBooleanValue(service, name, parseBool(value), settings.NoEnvironmentID)
	case "integer", "int":
		iv, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("integer: %w", err)
		}
		return settingsmgr.NewIntegerValue(service, name, iv, settings.NoEnvironmentID)
	default:
		return fmt.Errorf("unknown type %q (string|boolean|integer)", typ)
	}
}

func (s *dbStore) UpdateSetting(service, name, typ, value string) error {
	// Delete-then-create keeps the value fresh without a generic setter.
	if err := settingsmgr.DeleteValue(service, name, settings.NoEnvironmentID); err != nil {
		return err
	}
	return s.AddSetting(service, name, typ, value)
}

func (s *dbStore) DeleteSetting(service, name string) error {
	return settingsmgr.DeleteValue(service, name, settings.NoEnvironmentID)
}

func (s *dbStore) Permissions(username string) ([]permRow, error) {
	ps, err := adminUsers.GetAllPermissions(username)
	if err != nil {
		return nil, err
	}
	out := make([]permRow, 0, len(ps))
	for _, pr := range ps {
		out = append(out, permRow{
			Username:    pr.Username,
			Environment: pr.Environment,
			AccessType:  accessTypeName(pr.AccessType),
			AccessValue: pr.AccessValue,
			GrantedBy:   pr.GrantedBy,
		})
	}
	return out, nil
}

// parseBool tolerates common truthy strings.
func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "y", "1", "on":
		return true
	}
	return false
}

// accessTypeName maps a users.AccessType int to a readable label.
func accessTypeName(t int) string {
	switch t {
	case 0:
		return "admin"
	case 1:
		return "user"
	case 2:
		return "query"
	case 3:
		return "carve"
	default:
		return strconv.Itoa(t)
	}
}
