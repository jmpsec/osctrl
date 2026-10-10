package vulns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// nvd.go — CVEs with application CPEs from the NVD CVE API 2.0, for
// "possible" findings on Windows programs, macOS apps, Homebrew and
// Chocolatey packages (--vuln-nvd-enabled).

const (
	DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	sourceNVD     = "nvd"
	nvdPageSize   = 2000
	// nvdMaxWindow is the longest lastModStartDate..lastModEndDate range the
	// API accepts; an older cursor is resynced in full.
	nvdMaxWindow = 120 * 24 * time.Hour
	// nvdOverlap reaches each incremental window back past the cursor. NVD
	// indexes some records after their lastModified time, and a record
	// modified while a window is paged can shift another past a page
	// boundary; re-reading a day of changes is idempotent and cheap.
	nvdOverlap   = 24 * time.Hour
	nvdAttempts  = 3
	nvdRetryWait = 30 * time.Second
	// nvdQueryTime is the API's date format, with an explicit offset.
	nvdQueryTime = "2006-01-02T15:04:05.000-07:00"
)

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	Configurations []nvdConfiguration `json:"configurations"`
	References     []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
}

type nvdMetric struct {
	Type     string `json:"type"` // Primary or Secondary
	CVSSData struct {
		VectorString string `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// NVDSource syncs CVEs that list application CPEs from the NVD CVE API 2.0,
// or from a mirror serving the same responses.
type NVDSource struct {
	db      *gorm.DB
	baseURL string
	fetch   fetcher // carries the apiKey header when a key is set
	keyed   bool
	now     func() time.Time
	// sleep paces requests and retries; tests replace it.
	sleep func(ctx context.Context, d time.Duration) error
}

func newNVDSource(db *gorm.DB, baseURL, apiKey string, f fetcher, now func() time.Time) *NVDSource {
	if apiKey != "" {
		f.header = http.Header{"apiKey": {apiKey}}
		// The key is for the configured host only: Go forwards custom
		// headers on redirects, so drop it when one leaves that host.
		client := *f.client
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Host != via[0].URL.Host {
				req.Header.Del("apiKey")
			}
			return nil
		}
		f.client = &client
	}
	return &NVDSource{db: db, baseURL: baseURL, fetch: f, keyed: apiKey != "", now: now, sleep: sleepCtx}
}

// sleepCtx waits d, or less if ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pause is the documented pacing: 5 requests per 30 seconds without a key,
// 50 with one.
func (s *NVDSource) pause() time.Duration {
	if s.keyed {
		return 600 * time.Millisecond
	}
	return 6 * time.Second
}

// Sync pages through CVEs modified since the cursor (all of them on the
// first run). Pages are stored as they arrive; the cursor moves only when
// every page is in, so a failed run is retried from the same point.
func (s *NVDSource) Sync(ctx context.Context) (SyncResult, error) {
	var state SyncState
	if err := s.db.Where("source = ?", sourceNVD).Limit(1).Find(&state).Error; err != nil {
		return SyncResult{}, err
	}
	start := s.now()
	q := url.Values{"resultsPerPage": {strconv.Itoa(nvdPageSize)}}
	since := state.Cursor.Add(-nvdOverlap)
	if state.LastSuccess != nil && start.Sub(since) < nvdMaxWindow {
		q.Set("lastModStartDate", since.UTC().Format(nvdQueryTime))
		q.Set("lastModEndDate", start.UTC().Format(nvdQueryTime))
	}
	res, err := s.pages(ctx, q, !q.Has("lastModStartDate"))
	if err != nil {
		recordFailure(s.db, sourceNVD, err, s.now())
		return res, err
	}
	return res, recordSuccess(s.db, sourceNVD, start, res, s.now())
}

// pages reads every page of q. A truncated answer is an error, never a
// complete sync: the cursor would move past CVEs that were never read.
func (s *NVDSource) pages(ctx context.Context, q url.Values, full bool) (SyncResult, error) {
	var res SyncResult
	for index := 0; ; {
		q.Set("startIndex", strconv.Itoa(index))
		page, err := s.page(ctx, s.baseURL+"?"+q.Encode())
		if err != nil {
			return res, err
		}
		batch := make([]parsedAdvisory, 0, len(page.Vulnerabilities))
		var products []CPEProduct
		for _, v := range page.Vulnerabilities {
			p, prods, err := parseNVD(v.CVE)
			if err != nil {
				res.Skipped++
				continue
			}
			batch = append(batch, p)
			products = append(products, prods...)
			res.Written++
		}
		if err := s.store(batch, products); err != nil {
			return res, err
		}
		index += len(page.Vulnerabilities)
		if index >= page.TotalResults {
			if full && page.TotalResults == 0 {
				return res, errors.New("NVD listed no CVEs for a full sync")
			}
			return res, nil
		}
		if len(page.Vulnerabilities) == 0 {
			return res, fmt.Errorf("NVD returned an empty page at %d of %d results", index, page.TotalResults)
		}
		if err := s.sleep(ctx, s.pause()); err != nil {
			return res, err
		}
	}
}

// page fetches one page, retrying rate limiting (NVD answers 403 or 429) and
// server errors.
func (s *NVDSource) page(ctx context.Context, u string) (nvdPage, error) {
	var err error
	for attempt := range nvdAttempts {
		if attempt > 0 {
			if serr := s.sleep(ctx, nvdRetryWait); serr != nil {
				return nvdPage{}, serr
			}
		}
		var raw []byte
		if raw, err = s.fetch.readAll(ctx, u); err == nil {
			var p nvdPage
			if err := json.Unmarshal(raw, &p); err != nil {
				return nvdPage{}, fmt.Errorf("parse NVD page: %w", err)
			}
			return p, nil
		}
		if !retryable(err) {
			return nvdPage{}, err
		}
	}
	return nvdPage{}, err
}

func retryable(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code == http.StatusForbidden || se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return !errors.Is(err, ErrTooLarge) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// store writes one page. A CVE id an OSV record already uses stays the OSV
// record's: NVD never overwrites it.
func (s *NVDSource) store(batch []parsedAdvisory, products []CPEProduct) error {
	if len(batch) == 0 {
		return nil
	}
	ids := make([]string, len(batch))
	for i, p := range batch {
		ids[i] = p.Advisory.ID
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var owned []string
		if err := tx.Model(&Advisory{}).Where("id IN ? AND source <> ?", ids, AdvisorySourceNVD).Pluck("id", &owned).Error; err != nil {
			return err
		}
		for _, p := range batch {
			if slices.Contains(owned, p.Advisory.ID) {
				continue
			}
			if err := storeAdvisory(tx, p); err != nil {
				return err
			}
		}
		if len(products) == 0 {
			return nil
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(products, 500).Error
	})
}

// parseNVD converts one CVE. Only application CPEs (part "a") that NVD marks
// vulnerable are kept. A CVE without any, or a rejected one, leaves no
// advisory behind: storeAdvisory removes what an earlier version stored.
func parseNVD(c nvdCVE) (parsedAdvisory, []CPEProduct, error) {
	if c.ID == "" {
		return parsedAdvisory{}, nil, errors.New("CVE has no id")
	}
	var desc string
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	p := parsedAdvisory{Withdrawn: c.VulnStatus == "Rejected"}
	p.Advisory = Advisory{
		ID:        clipTo(c.ID, 128),
		Source:    AdvisorySourceNVD,
		Summary:   clipTo(desc, maxSummaryLen),
		Published: nvdTime(c.Published),
		Modified:  nvdTime(c.LastModified),
		Severity:  SeverityUnknown,
	}
	if p.Withdrawn {
		return p, nil, nil
	}
	if vector, score, ok := nvdScore(c.Metrics); ok {
		p.Advisory.CVSSVector, p.Advisory.CVSSScore = clip(vector), score
		p.Advisory.Severity = severityFromScore(score)
	}
	refs := []string{}
	for _, r := range c.References {
		if r.URL != "" && len(refs) < maxReferences {
			refs = append(refs, r.URL)
		}
	}
	refJSON, _ := json.Marshal(refs)
	p.Advisory.RefURLs = string(refJSON)
	// The CVE is its own alias, so the KEV refresh (which joins aliases)
	// flags it.
	p.Aliases = []Alias{{AdvisoryID: p.Advisory.ID, Alias: p.Advisory.ID}}

	type product struct {
		ranges   []cpeRange
		versions []string
	}
	byKey := map[string]*product{}
	var keys []string
	var products []CPEProduct
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				n, ok := parseCPE(m.Criteria)
				if !m.Vulnerable || !ok || n.Part != "a" || n.Version == "-" || len(n.Vendor) > 128 || len(n.Product) > 128 {
					continue
				}
				key := n.Vendor + ":" + n.Product
				pr := byKey[key]
				if pr == nil {
					pr = &product{ranges: []cpeRange{}, versions: []string{}}
					byKey[key] = pr
					keys = append(keys, key)
					products = append(products, CPEProduct{Vendor: n.Vendor, Product: n.Product})
				}
				if n.Version != "*" && n.Version != "" {
					pr.versions = append(pr.versions, n.Version)
					continue
				}
				pr.ranges = append(pr.ranges, cpeRange{
					StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
					EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding,
				})
			}
		}
	}
	for _, key := range keys {
		ranges, _ := json.Marshal(byKey[key].ranges)
		versions, _ := json.Marshal(byKey[key].versions)
		p.Affected = append(p.Affected, Affected{
			AdvisoryID: p.Advisory.ID, Ecosystem: cpeEcosystem, Package: key,
			Ranges: string(ranges), Versions: string(versions),
		})
	}
	return p, products, nil
}

// nvdScore picks a CVSS v3.1, then v3.0, then v4.0 vector, the primary
// (NVD's own) score before a secondary one.
func nvdScore(m nvdMetrics) (string, float64, bool) {
	for _, list := range [][]nvdMetric{m.V31, m.V30, m.V40} {
		for _, primary := range []bool{true, false} {
			for _, x := range list {
				if (x.Type == "Primary") != primary {
					continue
				}
				if score, ok := cvssScore(x.CVSSData.VectorString); ok {
					return x.CVSSData.VectorString, score, true
				}
			}
		}
	}
	return "", 0, false
}

// nvdTime parses NVD timestamps, which carry no zone (UTC).
func nvdTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// dropNVD removes NVD data once --vuln-nvd-enabled is off: possible findings
// resolve, borrowed severities revert, and an NVD sync row that will never
// update again stops marking every feed stale. It also runs on data an
// interrupted first sync left without a sync row.
func dropNVD(db *gorm.DB, now time.Time) error {
	var n int64
	for _, q := range []*gorm.DB{
		db.Model(&SyncState{}).Where("source = ?", sourceNVD),
		db.Model(&Advisory{}).Where("source = ?", AdvisorySourceNVD),
		db.Model(&CPEProduct{}),
		db.Model(&Finding{}).Where("ecosystem = ? AND resolved_at IS NULL", cpeEcosystem),
	} {
		var c int64
		if err := q.Count(&c).Error; err != nil {
			return err
		}
		n += c
	}
	if n == 0 {
		return nil
	}
	nvdIDs := func(tx *gorm.DB) *gorm.DB {
		return tx.Model(&Advisory{}).Select("id").Where("source = ?", AdvisorySourceNVD)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("advisory_id IN (?)", nvdIDs(tx)).Delete(&Affected{}).Error; err != nil {
			return err
		}
		if err := tx.Where("advisory_id IN (?)", nvdIDs(tx)).Delete(&Alias{}).Error; err != nil {
			return err
		}
		if err := tx.Where("source = ?", AdvisorySourceNVD).Delete(&Advisory{}).Error; err != nil {
			return err
		}
		if err := tx.Where("1 = 1").Delete(&CPEProduct{}).Error; err != nil {
			return err
		}
		// Nodes silent for 30 days are never re-matched; resolve here.
		if err := tx.Model(&Finding{}).Where("ecosystem = ? AND resolved_at IS NULL", cpeEcosystem).
			Update("resolved_at", now).Error; err != nil {
			return err
		}
		return tx.Where("source = ?", sourceNVD).Delete(&SyncState{}).Error
	}); err != nil {
		return err
	}
	if err := refreshFlags(db); err != nil {
		return err
	}
	return db.Model(&NodeState{}).Where("1 = 1").Update("matched_at", nil).Error
}
