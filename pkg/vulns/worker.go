package vulns

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	DefaultOSVURL       = "https://osv-vulnerabilities.storage.googleapis.com"
	DefaultKEVURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultSyncInterval = 6 * time.Hour
	DefaultMaxDownload  = int64(2048) << 20

	workerName    = "worker"
	tickInterval  = time.Minute
	leaseTTL      = 3 * time.Minute
	failureRetry  = 15 * time.Minute
	housekeepEach = time.Hour
	matchBatch    = 500
	staleNodeAge  = 30 * 24 * time.Hour
	// escalationRetention keeps escalations long enough for any watcher
	// that is running to read them.
	escalationRetention = 30 * 24 * time.Hour
	// nvdDropAfter is how long a replica with NVD off waits after the last
	// NVD-enabled tick before deleting NVD data: replicas configured apart
	// would otherwise delete and fully resync it on every lease handover.
	nvdDropAfter = time.Hour
)

// Config is the worker's view of the --vuln-* flags.
type Config struct {
	OSVURL       string
	KEVURL       string
	Ecosystems   []string // OSV directories; empty = what the fleet reports
	SyncInterval time.Duration
	Retention    time.Duration
	MaxDownload  int64
	HTTPClient   *http.Client
	// NVD CPE matching (--vuln-nvd-*). The key is a secret: it travels only
	// as a request header.
	NVDEnabled bool
	NVDURL     string
	NVDAPIKey  string
}

// Worker syncs feeds and keeps findings current. Every osctrl-api replica
// runs one; a lease row lets exactly one of them work at a time.
type Worker struct {
	db      *gorm.DB
	cfg     Config
	owner   string
	host    string // stable across restarts, unlike owner
	fetch   fetcher
	osv     *OSVSource
	nvd     *NVDSource // nil while --vuln-nvd-enabled is off
	matcher *Matcher
	now     func() time.Time
}

// ParseEcosystems splits the --vuln-ecosystems value.
func ParseEcosystems(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NewWorker migrates the tables and validates the configuration.
func NewWorker(db *gorm.DB, cfg Config) (*Worker, error) {
	if cfg.OSVURL == "" {
		cfg.OSVURL = DefaultOSVURL
	}
	if cfg.KEVURL == "" {
		cfg.KEVURL = DefaultKEVURL
	}
	if cfg.NVDEnabled && cfg.NVDURL == "" {
		cfg.NVDURL = DefaultNVDURL
	}
	urls := []string{cfg.OSVURL, cfg.KEVURL}
	if cfg.NVDEnabled {
		urls = append(urls, cfg.NVDURL)
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("feed URL %q must be an http or https URL", raw)
		}
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = DefaultSyncInterval
	}
	if cfg.MaxDownload <= 0 {
		cfg.MaxDownload = DefaultMaxDownload
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Minute}
	}
	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("migrate vulnerability tables: %w", err)
	}
	host, _ := os.Hostname()
	w := &Worker{
		db:    db,
		cfg:   cfg,
		host:  host,
		owner: fmt.Sprintf("%s-%d-%x", host, os.Getpid(), rand.Uint64()),
		fetch: fetcher{client: cfg.HTTPClient, maxBytes: cfg.MaxDownload},
		now:   time.Now,
	}
	clock := func() time.Time { return w.now() }
	w.osv = &OSVSource{db: db, baseURL: cfg.OSVURL, fetch: w.fetch, now: clock}
	if cfg.NVDEnabled {
		w.nvd = newNVDSource(db, cfg.NVDURL, cfg.NVDAPIKey, w.fetch, clock)
	}
	w.matcher = &Matcher{DB: db, now: clock, CPE: cfg.NVDEnabled}
	return w, nil
}

// Run ticks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		if err := w.Tick(ctx); err != nil {
			log.Warn().Err(err).Msg("vulns: worker tick failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick does one round of work if this replica holds the lease.
func (w *Worker) Tick(ctx context.Context) error {
	ok, err := w.acquireLease()
	if err != nil || !ok {
		return err
	}
	// A feed download can outlast the lease; keep renewing while working.
	renewCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(leaseTTL / 3)
		defer t.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-t.C:
				_, _ = w.acquireLease()
			}
		}
	}()

	var ws WorkerState
	if err := w.db.Where("name = ?", workerName).First(&ws).Error; err != nil {
		return err
	}
	switch {
	case w.nvd != nil:
		if err := w.db.Model(&WorkerState{}).Where("name = ?", workerName).
			Updates(map[string]any{"nvd_active_at": w.now(), "nvd_active_by": w.host}).Error; err != nil {
			return err
		}
	case ws.NVDActiveAt != nil && ws.NVDActiveBy != w.host && w.now().Sub(*ws.NVDActiveAt) < nvdDropAfter:
		log.Warn().Msg("vulns: another osctrl-api replica runs with --vuln-nvd-enabled; keeping NVD data. Set the flag the same on every replica.")
	default:
		if err := dropNVD(w.db, w.now()); err != nil {
			return err
		}
	}
	dirs, err := w.ecosystemDirs()
	if err != nil {
		return err
	}
	due, err := w.syncDue(ws, dirs)
	if err != nil {
		return err
	}
	if due {
		w.syncAll(ctx, dirs)
	}
	if err := w.matchDirty(); err != nil {
		return err
	}
	if ws.LastHousekeepAt == nil || w.now().Sub(*ws.LastHousekeepAt) >= housekeepEach {
		return w.housekeep()
	}
	return nil
}

// acquireLease takes or renews the lease. It succeeds when the row is free,
// expired, or already ours.
func (w *Worker) acquireLease() (bool, error) {
	now := w.now()
	res := w.db.Model(&WorkerState{}).
		Where("name = ? AND (owner = ? OR lease_until < ?)", workerName, w.owner, now).
		Updates(map[string]any{"owner": w.owner, "lease_until": now.Add(leaseTTL)})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 1 {
		return true, nil
	}
	// No row yet: the first replica to insert one wins.
	res = w.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&WorkerState{Name: workerName, Owner: w.owner, LeaseUntil: now.Add(leaseTTL)})
	return res.RowsAffected == 1, res.Error
}

// RequestSync asks the worker to sync on its next tick. Used by the API.
func RequestSync(db *gorm.DB, at time.Time) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"sync_requested_at"}),
	}).Create(&WorkerState{Name: workerName, SyncRequestedAt: &at}).Error
}

// ecosystemDirs is the configured allow-list, or else every OSV directory
// the fleet's inventory needs.
func (w *Worker) ecosystemDirs() ([]string, error) {
	if len(w.cfg.Ecosystems) > 0 {
		return w.cfg.Ecosystems, nil
	}
	var platforms, categories []string
	if err := w.db.Model(&NodeState{}).Distinct("os_platform").Pluck("os_platform", &platforms).Error; err != nil {
		return nil, err
	}
	if err := w.db.Model(&NodeSoftware{}).Distinct("category").Pluck("category", &categories).Error; err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range platforms {
		if d, ok := platformDirs[strings.ToLower(p)]; ok {
			set[d] = true
		}
	}
	for _, c := range categories {
		if d, ok := categoryDirs[c]; ok {
			set[d] = true
		}
	}
	return slices.Sorted(maps.Keys(set)), nil
}

func (w *Worker) syncDue(ws WorkerState, dirs []string) (bool, error) {
	if ws.SyncRequestedAt != nil || ws.LastSyncAt == nil {
		return true, nil
	}
	since := w.now().Sub(*ws.LastSyncAt)
	if since >= w.cfg.SyncInterval {
		return true, nil
	}
	if since < failureRetry {
		return false, nil
	}
	if ws.LastSyncFailed {
		return true, nil
	}
	// A new ecosystem appeared in the fleet, or NVD was turned on, since the
	// last sync.
	sources := make([]string, 0, len(dirs)+1)
	for _, d := range dirs {
		sources = append(sources, osvSourcePrefix+d)
	}
	if w.nvd != nil {
		sources = append(sources, sourceNVD)
	}
	if len(sources) == 0 {
		return false, nil
	}
	var synced int64
	if err := w.db.Model(&SyncState{}).Where("source IN ? AND last_success IS NOT NULL", sources).Count(&synced).Error; err != nil {
		return false, err
	}
	return int(synced) < len(sources), nil
}

func (w *Worker) syncAll(ctx context.Context, dirs []string) {
	start := w.now()
	failed, changed := false, false
	for _, dir := range dirs {
		res, err := w.osv.Sync(ctx, dir)
		if err != nil {
			failed = true
			log.Warn().Err(err).Str("ecosystem", dir).Msg("vulns: OSV sync failed")
			continue
		}
		changed = changed || res.Written > 0
	}
	if w.nvd != nil {
		res, err := w.nvd.Sync(ctx)
		if err != nil {
			failed = true
			log.Warn().Err(err).Msg("vulns: NVD sync failed")
		} else {
			changed = changed || res.Written > 0
		}
	}
	if err := syncKEV(ctx, w.db, w.fetch, w.cfg.KEVURL, w.now()); err != nil {
		failed = true
		log.Warn().Err(err).Msg("vulns: KEV sync failed")
	}
	if changed {
		if err := refreshFlags(w.db, w.now()); err != nil {
			log.Warn().Err(err).Msg("vulns: refreshing advisory flags failed")
		}
		// ponytail: any advisory change re-matches the whole fleet (one
		// indexed lookup per node and category). Target only nodes holding
		// the touched (ecosystem, package) pairs if this gets slow.
		if err := w.db.Model(&NodeState{}).Where("1 = 1").Update("matched_at", nil).Error; err != nil {
			log.Warn().Err(err).Msg("vulns: marking nodes for re-matching failed")
		}
	}
	if err := w.db.Model(&WorkerState{}).Where("name = ?", workerName).
		// The end time: a long failed sync then waits failureRetry before
		// running again instead of starving matching.
		Updates(map[string]any{"last_sync_at": w.now(), "last_sync_failed": failed}).Error; err != nil {
		log.Warn().Err(err).Msg("vulns: recording sync failed")
	}
	// A request made while this sync ran is kept for the next tick.
	_ = w.db.Model(&WorkerState{}).Where("name = ? AND sync_requested_at <= ?", workerName, start).
		Update("sync_requested_at", nil).Error
}

// matchDirty re-matches nodes whose inventory changed (or whose advisories
// did) since they were last matched. Nodes silent for 30 days are skipped.
func (w *Worker) matchDirty() error {
	var uuids []string
	if err := w.db.Model(&NodeState{}).
		Where("(matched_at IS NULL OR matched_at < inventory_at) AND inventory_at > ?", w.now().Add(-staleNodeAge)).
		Order("inventory_at").Limit(matchBatch).Pluck("node_uuid", &uuids).Error; err != nil {
		return err
	}
	for _, uuid := range uuids {
		if err := w.matcher.MatchNode(uuid); err != nil {
			log.Warn().Err(err).Str("node", uuid).Msg("vulns: matching failed")
		}
	}
	return nil
}

// housekeep purges old resolved findings and rows of deleted nodes. Node
// deletion lives in pkg/nodes and the CLI, which do not know about this
// feature, so orphans are swept here instead.
func (w *Worker) housekeep() error {
	now := w.now()
	if w.cfg.Retention > 0 {
		if err := w.db.Where("resolved_at IS NOT NULL AND resolved_at < ?", now.Add(-w.cfg.Retention)).Delete(&Finding{}).Error; err != nil {
			return err
		}
	}
	if err := w.db.Where("created_at < ?", now.Add(-escalationRetention)).Delete(&Escalation{}).Error; err != nil {
		return err
	}
	known := w.db.Model(&nodes.OsqueryNode{}).Select("uuid")
	for _, model := range []any{&NodeSoftware{}, &Finding{}, &NodeState{}} {
		if err := w.db.Where("node_uuid NOT IN (?)", known).Delete(model).Error; err != nil {
			return err
		}
	}
	return w.db.Model(&WorkerState{}).Where("name = ?", workerName).Update("last_housekeep_at", now).Error
}
