package santa

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Binary is what osctrl knows about one file hash in an environment. The
// identity fields come from its newest kept event and are written by Santa
// clients. First and last seen, the machine count and the machine list come
// from santa_binary_machines and outlive event retention; the event counts
// only cover the events still kept.
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
	SigningChain []Cert `json:"signing_chain"`
	// When osctrl first and last received an event of the file
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Kept events of the file, and how many of them were blocks
	Events  int64 `json:"events"`
	Blocked int64 `json:"blocked"`
	// Distinct machines that reported the file
	Machines int64 `json:"machines"`
	// The machines that reported it most recently, at most MaxBinaryMachines
	MachineList []BinaryMachine `json:"machine_list"`
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

// MaxBinaryMachines caps the machine list of a binary.
const MaxBinaryMachines = 100

// Binary summarizes one file hash. It returns gorm.ErrRecordNotFound when the
// environment has neither a kept event nor a history row for it.
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
	history := func() *gorm.DB {
		return m.DB.Model(&BinaryMachine{}).Where("environment_id = ? AND sha256 = ?", envID, sha256)
	}
	b := Binary{SHA256: sha256}
	if err := history().Count(&b.Machines).Error; err != nil {
		return Binary{}, err
	}
	var newest Event
	err := events().Order("executed_at DESC, id DESC").First(&newest).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound) && b.Machines == 0:
		return Binary{}, err
	case errors.Is(err, gorm.ErrRecordNotFound):
		newest = Event{FileSHA256: sha256} // pruned: only the hash rule can match
	case err != nil:
		return Binary{}, err
	default:
		b.FileName, b.FilePath, b.TeamID, b.SigningID, b.CDHash = newest.FileName, newest.FilePath, newest.TeamID, newest.SigningID, newest.CDHash
		b.BundleID, b.BundleName, b.BundleVersion, b.BundlePath = newest.BundleID, newest.BundleName, newest.BundleVersion, newest.BundlePath
		b.SigningChain, b.LatestEventID, b.LatestMachineID, b.LatestCarve = newest.SigningChain, newest.ID, newest.MachineID, newest.CarveName
		if err := events().Count(&b.Events).Error; err != nil {
			return Binary{}, err
		}
		if err := events().Where("decision LIKE ?", "BLOCK%").Count(&b.Blocked).Error; err != nil {
			return Binary{}, err
		}
	}
	if err := history().Order("last_seen DESC, id DESC").Limit(MaxBinaryMachines).Find(&b.MachineList).Error; err != nil {
		return Binary{}, err
	}
	if len(b.MachineList) > 0 {
		var first BinaryMachine
		if err := history().Order("first_seen, id").First(&first).Error; err != nil {
			return Binary{}, err
		}
		b.FirstSeen, b.LastSeen = first.FirstSeen, b.MachineList[0].LastSeen
		if b.FileName == "" {
			b.FileName = b.MachineList[0].FileName
		}
		if err := m.attachHostnames(envID, b.MachineList); err != nil {
			return Binary{}, err
		}
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

// attachHostnames fills the hostname of each listed machine still known.
func (m *Manager) attachHostnames(envID uint, list []BinaryMachine) error {
	ids := make([]string, len(list))
	for i := range list {
		ids[i] = list[i].MachineID
	}
	var machines []Machine
	if err := m.DB.Select("machine_id", "hostname").Where("environment_id = ? AND machine_id IN ?", envID, ids).Find(&machines).Error; err != nil {
		return err
	}
	names := make(map[string]string, len(machines))
	for _, mc := range machines {
		names[mc.MachineID] = mc.Hostname
	}
	for i := range list {
		list[i].Hostname = names[list[i].MachineID]
	}
	return nil
}

type binaryKey struct {
	env          uint
	sha, machine string
}

// recordBinaryMachines adds stored events to santa_binary_machines on tx: one
// row per environment, file and machine, first seen at its first upload.
// Bundle listings are not executions and are left out.
// ponytail: rows are never pruned; they grow with distinct (file, machine)
// pairs. Prune by last_seen if that gets large.
func recordBinaryMachines(tx *gorm.DB, evs []Event, now time.Time) error {
	agg := map[binaryKey]*BinaryMachine{}
	var keys []binaryKey
	for _, e := range evs {
		if e.FileSHA256 == "" || e.MachineID == "" || e.Decision == DecisionBundleBinary {
			continue
		}
		k := binaryKey{e.EnvironmentID, strings.ToLower(e.FileSHA256), e.MachineID}
		row, ok := agg[k]
		if !ok {
			row = &BinaryMachine{EnvironmentID: k.env, SHA256: k.sha, MachineID: k.machine, FirstSeen: now, LastSeen: now}
			agg[k] = row
			keys = append(keys, k)
		}
		row.Events++
		row.FileName = e.FileName
	}
	// A fixed order keeps concurrent uploads from locking rows in different orders.
	slices.SortFunc(keys, func(a, b binaryKey) int {
		return cmp.Or(cmp.Compare(a.env, b.env), cmp.Compare(a.sha, b.sha), cmp.Compare(a.machine, b.machine))
	})
	for _, k := range keys {
		row := agg[k]
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "environment_id"}, {Name: "sha256"}, {Name: "machine_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"last_seen": now, "file_name": row.FileName,
				"events": gorm.Expr("santa_binary_machines.events + ?", row.Events),
			}),
		}).Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

// backfillBinaryMachines fills a new santa_binary_machines from the kept
// events, so binaries seen before it existed keep their first seen. It reads
// the events in batches and aggregates in Go: time aggregates do not scan
// portably. Another process migrating at the same time inserts the same rows;
// those are skipped.
func backfillBinaryMachines(db *gorm.DB) error {
	agg := map[binaryKey]*BinaryMachine{}
	var batch []Event
	err := db.Select("id", "environment_id", "file_sha256", "machine_id", "file_name", "created_at").
		Where("file_sha256 <> '' AND machine_id <> '' AND decision <> ?", DecisionBundleBinary).
		FindInBatches(&batch, 1000, func(*gorm.DB, int) error {
			for _, e := range batch {
				k := binaryKey{e.EnvironmentID, strings.ToLower(e.FileSHA256), e.MachineID}
				row, ok := agg[k]
				if !ok {
					row = &BinaryMachine{EnvironmentID: k.env, SHA256: k.sha, MachineID: k.machine, FirstSeen: e.CreatedAt, LastSeen: e.CreatedAt}
					agg[k] = row
				}
				row.Events++
				if !e.CreatedAt.Before(row.LastSeen) {
					row.LastSeen, row.FileName = e.CreatedAt, e.FileName
				}
				if e.CreatedAt.Before(row.FirstSeen) {
					row.FirstSeen = e.CreatedAt
				}
			}
			return nil
		}).Error
	if err != nil || len(agg) == 0 {
		return err
	}
	rows := make([]BinaryMachine, 0, len(agg))
	for _, r := range agg {
		rows = append(rows, *r)
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&rows, 200).Error
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
