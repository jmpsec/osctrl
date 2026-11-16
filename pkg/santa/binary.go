package santa

import (
	"fmt"
	"path"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Binary is what the stored events say about one file hash in an environment.
// The identity fields come from its newest event and are written by Santa
// clients. Dates and counts only cover the events still kept.
type Binary struct {
	SHA256        string `json:"sha256"`
	FileName      string `json:"file_name"`
	FilePath      string `json:"file_path"`
	TeamID        string `json:"team_id"`
	SigningID     string `json:"signing_id"`
	CDHash        string `json:"cd_hash"`
	BundleID      string `json:"bundle_id"`
	BundleName    string `json:"bundle_name"`
	BundleVersion string `json:"bundle_version"`
	BundlePath    string `json:"bundle_path"`
	// Leaf certificate first; empty when unsigned or not reported
	SigningChain []Cert    `json:"signing_chain"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	// Events of the file, and how many of them were blocks
	Events  int64 `json:"events"`
	Blocked int64 `json:"blocked"`
	// Distinct machines that reported the file
	Machines int64 `json:"machines"`
	// Rules of any scope naming the file, its team ID, signing ID, CDHash or leaf certificate
	Rules []Rule `json:"rules"`
	// Cached risk verdict, when risk checks are on
	Risk *Risk `json:"risk,omitempty"`
	// The newest event, to retrieve the file from the machine that last ran it
	LatestEventID   uint   `json:"latest_event_id"`
	LatestMachineID string `json:"latest_machine_id"`
	LatestCarve     string `json:"latest_carve"`
}

// ruleMatch narrows a rule query to the rules that name the file of ev: by its
// hash, team ID, signing ID, CDHash or leaf certificate.
func ruleMatch(db *gorm.DB, ev Event) *gorm.DB {
	ids := map[string]string{"TEAMID": strings.ToUpper(ev.TeamID), "SIGNINGID": ev.SigningID, "CDHASH": strings.ToLower(ev.CDHash)}
	if len(ev.SigningChain) > 0 {
		ids["CERTIFICATE"] = strings.ToLower(ev.SigningChain[0].SHA256)
	}
	match := db.Where("rule_type = ? AND identifier = ?", "BINARY", strings.ToLower(ev.FileSHA256))
	for typ, id := range ids {
		if id != "" {
			match = match.Or("rule_type = ? AND identifier = ?", typ, id)
		}
	}
	return match
}

// Binary summarizes the events of one file hash. It returns
// gorm.ErrRecordNotFound when the environment has no event for it.
func (m *Manager) Binary(envID uint, sha256 string) (Binary, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if !hex64.MatchString(sha256) {
		return Binary{}, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	}
	// ponytail: LOWER(file_sha256) is not indexed, so each query scans the
	// environment's kept events; add a hash index if the page gets slow.
	events := func() *gorm.DB {
		return m.DB.Model(&Event{}).Where("environment_id = ? AND LOWER(file_sha256) = ?", envID, sha256)
	}
	var newest, oldest Event
	if err := events().Order("executed_at DESC, id DESC").First(&newest).Error; err != nil {
		return Binary{}, err
	}
	if err := events().Order("executed_at, id").First(&oldest).Error; err != nil {
		return Binary{}, err
	}
	b := Binary{
		SHA256: sha256, FileName: newest.FileName, FilePath: newest.FilePath, TeamID: newest.TeamID, SigningID: newest.SigningID,
		CDHash: newest.CDHash, BundleID: newest.BundleID, BundleName: newest.BundleName, BundleVersion: newest.BundleVersion,
		BundlePath: newest.BundlePath, SigningChain: newest.SigningChain, FirstSeen: oldest.ExecutedAt, LastSeen: newest.ExecutedAt,
		LatestEventID: newest.ID, LatestMachineID: newest.MachineID, LatestCarve: newest.CarveName,
	}
	if err := events().Count(&b.Events).Error; err != nil {
		return Binary{}, err
	}
	if err := events().Where("decision LIKE ?", "BLOCK%").Count(&b.Blocked).Error; err != nil {
		return Binary{}, err
	}
	if err := events().Distinct("machine_id").Count(&b.Machines).Error; err != nil {
		return Binary{}, err
	}
	if err := m.DB.Where("environment_id = ?", envID).Where(ruleMatch(m.DB, newest)).Order("id").Find(&b.Rules).Error; err != nil {
		return Binary{}, err
	}
	risk, err := m.cachedRisk([]string{sha256})
	if err != nil {
		return Binary{}, err
	}
	b.Risk = risk[sha256]
	return b, nil
}

// Event returns one stored event of the environment.
func (m *Manager) Event(envID, id uint) (Event, error) {
	var ev Event
	err := m.DB.Where("environment_id = ? AND id = ?", envID, id).First(&ev).Error
	return ev, err
}

// FullPath is the path of the event's file: Santa reports the directory and
// the file name apart.
func (e Event) FullPath() string {
	if e.FilePath == "" || e.FileName == "" || path.Base(e.FilePath) == e.FileName {
		return e.FilePath
	}
	return path.Join(e.FilePath, e.FileName)
}

// SetEventCarve records the carve started to retrieve the event's file.
func (m *Manager) SetEventCarve(envID, id uint, name string) error {
	return m.DB.Model(&Event{}).Where("environment_id = ? AND id = ?", envID, id).Update("carve_name", name).Error
}
