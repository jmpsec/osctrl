// Package extensions stores osquery extension binaries, their assignments to
// environments and nodes, and the status osctrld reports for them.
package extensions

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

var (
	ErrInvalid             = errors.New("invalid extension input")
	ErrNotFound            = errors.New("extension not found")
	ErrDuplicate           = errors.New("extension name already exists")
	ErrAssigned            = errors.New("extension is assigned")
	ErrKept                = errors.New("extension is still on a host that could not remove it")
	ErrTooLarge            = errors.New("extension file is too large")
	ErrEmpty               = errors.New("extension file is empty")
	ErrTruncated           = errors.New("extension file upload was cut short")
	ErrCommandExecution    = errors.New("command-execution extensions can only be assigned to nodes")
	ErrNotCommandExecution = errors.New("only command-execution extensions can be assigned to nodes")
)

// nameRe is the same rule osctrld enforces; the name becomes a file name.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidName reports whether name is a valid extension name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

const maxVersion = 64

// Manager is the source of truth for extensions, shared by osctrl-api and
// osctrl-tls through SQL.
type Manager struct {
	db *gorm.DB
}

// NewManager migrates the extension tables and returns a manager.
func NewManager(db *gorm.DB) (*Manager, error) {
	if err := db.AutoMigrate(&Extension{}, &ExtensionFile{}, &ExtensionChunk{}, &EnvExtension{}, &NodeExtension{}, &NodeExtensionStatus{}); err != nil {
		return nil, fmt.Errorf("migrating extensions: %w", err)
	}
	return &Manager{db: db}, nil
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// Create adds an extension to the library.
func (m *Manager) Create(ext Extension) (*Extension, error) {
	if !ValidName(ext.Name) {
		return nil, fmt.Errorf("%w: name must match %s", ErrInvalid, nameRe)
	}
	if len(ext.Version) > maxVersion {
		return nil, fmt.Errorf("%w: version longer than %d", ErrInvalid, maxVersion)
	}
	// Names that differ only in case would share one file on case-insensitive hosts
	var n int64
	if err := m.db.Model(&Extension{}).Where("LOWER(name) = ?", strings.ToLower(ext.Name)).Count(&n).Error; err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, ext.Name)
	}
	e := Extension{
		Name:             ext.Name,
		Description:      ext.Description,
		Version:          ext.Version,
		CommandExecution: ext.CommandExecution,
		CreatedBy:        ext.CreatedBy,
		UpdatedBy:        ext.CreatedBy,
	}
	if err := m.db.Create(&e).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicate, ext.Name)
		}
		return nil, err
	}
	return &e, nil
}

// assigned reports whether any environment or node has the extension.
func assigned(tx *gorm.DB, id uint) (bool, error) {
	var n int64
	if err := tx.Model(&EnvExtension{}).Where("extension_id = ?", id).Count(&n).Error; err != nil || n > 0 {
		return n > 0, err
	}
	err := tx.Model(&NodeExtension{}).Where("extension_id = ?", id).Count(&n).Error
	return n > 0, err
}

// refuseKept returns ErrKept while any host reports the named extension kept,
// i.e. osctrld could not remove it.
func refuseKept(tx *gorm.DB, name string) error {
	var n int64
	if err := tx.Model(&NodeExtensionStatus{}).Where("name = ? AND result = ?", name, ResultKept).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrKept
	}
	return nil
}

// Update changes the description, version and, while the extension is not
// assigned anywhere, whether it is a command-execution extension. Switching
// command execution off is refused with ErrKept while a host reports it kept.
func (m *Manager) Update(id uint, desc, version string, commandExec *bool, by string) (*Extension, error) {
	if len(version) > maxVersion {
		return nil, fmt.Errorf("%w: version longer than %d", ErrInvalid, maxVersion)
	}
	var e Extension
	err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&e, id).Error; err != nil {
			return notFound(err)
		}
		updates := map[string]any{"description": desc, "version": version, "updated_by": by}
		if commandExec != nil && *commandExec != e.CommandExecution {
			busy, err := assigned(tx, id)
			if err != nil {
				return err
			}
			if busy {
				return ErrAssigned
			}
			if e.CommandExecution {
				// Switching it off would hide a host that still runs it
				if err := refuseKept(tx, e.Name); err != nil {
					return err
				}
			}
			updates["command_execution"] = *commandExec
		}
		if err := tx.Model(&e).Updates(updates).Error; err != nil {
			return err
		}
		return tx.First(&e, id).Error
	})
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Delete removes an unassigned extension, its files, the statuses reported
// for its name and the chunks no other file uses. A command-execution
// extension a host reported as kept is refused with ErrKept.
func (m *Manager) Delete(id uint) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var e Extension
		if err := tx.First(&e, id).Error; err != nil {
			return notFound(err)
		}
		busy, err := assigned(tx, id)
		if err != nil {
			return err
		}
		if busy {
			return ErrAssigned
		}
		if e.CommandExecution {
			// A host still running it would vanish from view with its status
			if err := refuseKept(tx, e.Name); err != nil {
				return err
			}
		}
		var shas []string
		if err := tx.Model(&ExtensionFile{}).Where("extension_id = ?", id).Distinct().Pluck("sha256", &shas).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("extension_id = ?", id).Delete(&ExtensionFile{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Delete(&Extension{}, id).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("name = ?", e.Name).Delete(&NodeExtensionStatus{}).Error; err != nil {
			return err
		}
		for _, sha := range shas {
			if err := dropUnreferenced(tx, sha); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get returns one extension.
func (m *Manager) Get(id uint) (*Extension, error) {
	var e Extension
	if err := m.db.First(&e, id).Error; err != nil {
		return nil, notFound(err)
	}
	return &e, nil
}

// List returns the library sorted by name, with files and assignment counts.
func (m *Manager) List() ([]ExtensionView, error) {
	var exts []Extension
	if err := m.db.Order("name").Find(&exts).Error; err != nil {
		return nil, err
	}
	var files []ExtensionFile
	if err := m.db.Order("platform, arch").Find(&files).Error; err != nil {
		return nil, err
	}
	type count struct {
		ExtensionID uint
		N           int64
	}
	countBy := func(model any) (map[uint]int64, error) {
		var rows []count
		err := m.db.Model(model).Select("extension_id, COUNT(*) AS n").Group("extension_id").Scan(&rows).Error
		out := make(map[uint]int64, len(rows))
		for _, r := range rows {
			out[r.ExtensionID] = r.N
		}
		return out, err
	}
	envCounts, err := countBy(&EnvExtension{})
	if err != nil {
		return nil, err
	}
	nodeCounts, err := countBy(&NodeExtension{})
	if err != nil {
		return nil, err
	}
	byExt := make(map[uint][]ExtensionFile)
	for _, f := range files {
		byExt[f.ExtensionID] = append(byExt[f.ExtensionID], f)
	}
	views := make([]ExtensionView, 0, len(exts))
	for _, e := range exts {
		views = append(views, ExtensionView{
			Extension:       e,
			Files:           byExt[e.ID],
			EnvAssignments:  envCounts[e.ID],
			NodeAssignments: nodeCounts[e.ID],
		})
	}
	return views, nil
}
