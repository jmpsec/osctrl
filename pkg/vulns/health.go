package vulns

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/pkg/health"
)

// health.go — the advisory feeds as a health page component.

func sourceFailing(s SyncState) bool {
	return s.LastErrorAt != nil && (s.LastSuccess == nil || s.LastErrorAt.After(*s.LastSuccess))
}

// HealthComponent reports feed health: degraded when a feed is failing,
// unknown before the first OSV sync, stale when data is old. It reads under
// ctx so a stalled database cannot hang the health page.
func (r *Reader) HealthComponent(ctx context.Context) health.Component {
	c := health.Component{ID: "vulnerabilities", Name: "Advisory feeds"}
	scoped := *r
	scoped.DB = r.DB.WithContext(ctx)
	fs, err := scoped.Feeds()
	if err != nil {
		c.Status = health.StatusUnknown
		c.Summary = "feed status unavailable: " + err.Error()
		return c
	}
	var failing []string
	for _, s := range fs.Sources {
		if sourceFailing(s) {
			failing = append(failing, s.Source)
		}
	}
	c.Details = map[string]any{
		"sources":         len(fs.Sources),
		"failing_sources": strings.Join(failing, ", "),
		"last_sync_at":    fs.LastSyncAt,
		"sync_requested":  fs.SyncRequestedAt != nil,
	}
	switch {
	case len(failing) > 0:
		c.Status = health.StatusDegraded
		c.Summary = fmt.Sprintf("%d of %d feeds failing: %s", len(failing), len(fs.Sources), strings.Join(failing, ", "))
	case !fs.Loaded:
		c.Status = health.StatusUnknown
		c.Summary = "advisory data not loaded yet"
	case fs.Stale:
		c.Status = health.StatusStale
		c.Summary = "advisory data is out of date"
	default:
		c.Status = health.StatusOperational
		c.Summary = fmt.Sprintf("%d feeds in sync", len(fs.Sources))
	}
	return c
}
