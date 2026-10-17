package extensions

import (
	"regexp"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const maxStatusError = 1024

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Results osctrld reports: ok and rejected for an install or update, removed
// and kept for a removal that worked or failed.
const (
	ResultOK       = "ok"
	ResultRejected = "rejected"
	ResultRemoved  = "removed"
	ResultKept     = "kept"
)

var results = map[string]bool{ResultOK: true, ResultRejected: true, ResultRemoved: true, ResultKept: true}

// ValidSHA256 reports whether s is a lowercase hex SHA-256.
func ValidSHA256(s string) bool { return shaRe.MatchString(s) }

// RecordStatus stores what osctrld reported, one row per node and extension
// name. Entries with an invalid name, SHA-256 or result, or naming an
// extension not in the library, are dropped; errors are capped at 1 KiB.
func (m *Manager) RecordStatus(nodeUUID string, envID uint, s []types.OsctrldExtensionStatus, at time.Time) error {
	var valid []types.OsctrldExtensionStatus
	var names []string
	for _, st := range s {
		if !ValidName(st.Name) || !ValidSHA256(st.SHA256) || !results[st.Result] {
			continue
		}
		valid = append(valid, st)
		names = append(names, st.Name)
	}
	if len(valid) == 0 {
		return nil
	}
	// Only library names, so a node cannot grow its rows without bound.
	var known []string
	if err := m.db.Model(&Extension{}).Where("name IN ?", names).Pluck("name", &known).Error; err != nil {
		return err
	}
	isKnown := make(map[string]bool, len(known))
	for _, n := range known {
		isKnown[n] = true
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		for _, st := range valid {
			if !isKnown[st.Name] {
				continue
			}
			row := &NodeExtensionStatus{
				NodeUUID:      nodeUUID,
				Name:          st.Name,
				EnvironmentID: envID,
				SHA256:        st.SHA256,
				Result:        st.Result,
				Error:         capError(st.Error),
				ReportedAt:    at,
			}
			// Node clock values outside what every database stores are dropped.
			if y := st.At.Year(); y >= 1970 && y <= 9999 {
				t := st.At
				row.At = &t
			}
			err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "node_uuid"}, {Name: "name"}},
				DoUpdates: clause.AssignmentColumns([]string{"environment_id", "sha256", "result", "error", "at", "reported_at", "updated_at"}),
			}).Create(row).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// capError cuts e to maxStatusError bytes without splitting a UTF-8 rune
// (Postgres rejects invalid UTF-8 in text columns).
func capError(e string) string {
	if len(e) <= maxStatusError {
		return e
	}
	return strings.ToValidUTF8(e[:maxStatusError], "")
}

// NodeStatuses returns the node's last reported statuses, by name.
func (m *Manager) NodeStatuses(nodeUUID string) ([]NodeExtensionStatus, error) {
	var rows []NodeExtensionStatus
	err := m.db.Where("node_uuid = ?", nodeUUID).Order("name").Find(&rows).Error
	return rows, err
}
