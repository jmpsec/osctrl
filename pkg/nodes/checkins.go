package nodes

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Checkin carries the observation time, not the later database flush time.
type Checkin struct {
	NodeID uint
	IP     string
	SeenAt time.Time
}

// UpdateCheckins persists each node's latest observation without resurrecting
// deleted nodes or allowing a delayed replica to move last_seen backwards.
func (n *NodeManager) UpdateCheckins(updates map[uint]Checkin) error {
	ids := make([]uint, 0, len(updates))
	for id, ev := range updates {
		if id == 0 || id != ev.NodeID || ev.SeenAt.IsZero() {
			return fmt.Errorf("invalid check-in for node %d", id)
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	precision := time.Nanosecond
	switch n.DB.Dialector.Name() {
	case "mysql":
		precision = time.Millisecond // GORM's default DATETIME(3).
	case "postgres":
		precision = time.Microsecond
	}
	// At most 700 bind parameters, including IDs, for older SQLite limits.
	const chunkSize = 100
	for start := 0; start < len(ids); start += chunkSize {
		chunk := ids[start:min(start+chunkSize, len(ids))]
		var seen, ip strings.Builder
		seen.WriteString("CASE")
		ip.WriteString("CASE")
		var seenArgs, ipArgs []any
		for _, id := range chunk {
			ev := updates[id]
			// Compare at storage precision. The first persisted observation wins
			// ties, preventing a delayed event from exploiting timestamp rounding.
			ev.SeenAt = ev.SeenAt.Truncate(precision)
			seen.WriteString(" WHEN id = ? AND (last_seen IS NULL OR last_seen < ?) THEN ?")
			seenArgs = append(seenArgs, id, ev.SeenAt, ev.SeenAt)
			if ev.IP != "" {
				ip.WriteString(" WHEN id = ? AND (last_seen IS NULL OR last_seen < ?) THEN ?")
				ipArgs = append(ipArgs, id, ev.SeenAt, ev.IP)
			}
		}
		seen.WriteString(" ELSE last_seen END")
		columns := map[string]any{"last_seen": gorm.Expr(seen.String(), seenArgs...)}
		if len(ipArgs) > 0 {
			ip.WriteString(" ELSE ip_address END")
			columns["ip_address"] = gorm.Expr(ip.String(), ipArgs...)
		}
		// Each chunk is one atomic statement; avoid a BEGIN/COMMIT round trip
		// around it. GORM keeps the soft-delete predicate and binds all values.
		if err := n.DB.Session(&gorm.Session{SkipDefaultTransaction: true}).
			Model(&OsqueryNode{}).Where("id IN ?", chunk).UpdateColumns(columns).Error; err != nil {
			return fmt.Errorf("update node check-ins: %w", err)
		}
	}
	return nil
}
