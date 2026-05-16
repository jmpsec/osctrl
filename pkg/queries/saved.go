package queries

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// SavedQuery as abstraction of a saved query to be used in distributed, schedule or packs.
//
// Composite unique index on (name, environment_id) — gorm AutoMigrate emits
// it as `idx_saved_query_name_env`. This is the structural fix for the
// TOCTOU race in SavedQueryCreateHandler: a concurrent pair of POSTs with
// the same name + env both pass the SavedExists precheck, both attempt
// CreateSaved; with the unique index, the second Create returns a
// duplicate-key error and the handler can map it to 409 cleanly.
type SavedQuery struct {
	gorm.Model
	Name          string `gorm:"uniqueIndex:idx_saved_query_name_env"`
	Creator       string
	Query         string
	EnvironmentID uint `gorm:"uniqueIndex:idx_saved_query_name_env"`
	ExtraData     string
}

// SavedQueryListPage is the canonical paginated-list result for saved queries.
type SavedQueryListPage struct {
	Items      []SavedQuery
	TotalItems int64
}

// SavedQuerySortableColumns is the closed set of columns external callers may
// sort by. Enforced in GetSavedByEnvPaged. Mirrors QuerySortableColumns.
var SavedQuerySortableColumns = map[string]string{
	"name":    "name",
	"creator": "creator",
	"created": "created_at",
	"updated": "updated_at",
}

// GetSavedByCreator to get a saved query by creator
func (q *Queries) GetSavedByCreator(creator string, envid uint) ([]SavedQuery, error) {
	var saved []SavedQuery
	if err := q.DB.Where("creator = ? AND environment_id = ?", creator, envid).Find(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// GetSaved to get a saved query by name + creator within an environment.
// Returns gorm.ErrRecordNotFound when no matching row exists — callers can
// use errors.Is(err, gorm.ErrRecordNotFound) to detect that case.
func (q *Queries) GetSaved(name, creator string, envid uint) (SavedQuery, error) {
	var saved SavedQuery
	if err := q.DB.Where("creator = ? AND name = ? AND environment_id = ?", creator, name, envid).First(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// GetSavedByEnv returns a saved query by name within an environment without
// scoping by creator — used by env admins who can manage any saved query.
// Returns gorm.ErrRecordNotFound when no matching row exists.
func (q *Queries) GetSavedByEnv(name string, envid uint) (SavedQuery, error) {
	var saved SavedQuery
	if err := q.DB.Where("name = ? AND environment_id = ?", name, envid).First(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// SavedExists reports whether a saved query with the given name exists in the
// environment, irrespective of creator.
func (q *Queries) SavedExists(name string, envid uint) bool {
	var count int64
	if err := q.DB.Model(&SavedQuery{}).Where("name = ? AND environment_id = ?", name, envid).Count(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// GetSavedByEnvPaged returns a page of saved queries for an env, with optional
// free-text search and an allowlisted sort column. pageSize is clamped to
// [1, 500]; pageSize <= 0 defaults to 50. page is 1-indexed.
func (q *Queries) GetSavedByEnvPaged(envid uint, search string, page, pageSize int, sortColumn string, desc bool) (SavedQueryListPage, error) {
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	dbCol, ok := SavedQuerySortableColumns[sortColumn]
	if !ok || sortColumn == "" {
		dbCol = "created_at"
		desc = true
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	orderExpr := fmt.Sprintf("%s %s", dbCol, dir)

	db := q.DB.Model(&SavedQuery{}).Where("environment_id = ?", envid)
	if search != "" {
		like := "%" + search + "%"
		db = db.Where("name LIKE ? OR creator LIKE ? OR query LIKE ?", like, like, like)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return SavedQueryListPage{}, err
	}
	var items []SavedQuery
	if err := db.Order(orderExpr).Offset(offset).Limit(pageSize).Find(&items).Error; err != nil {
		return SavedQueryListPage{}, err
	}
	return SavedQueryListPage{Items: items, TotalItems: total}, nil
}

// ErrSavedQueryExists is returned by CreateSaved when the underlying
// unique index on (name, environment_id) rejects the insert because a
// row with the same key already exists. Callers should map this to a
// 409 Conflict response.
var ErrSavedQueryExists = errors.New("saved query already exists")

// CreateSaved persists a new saved query. Returns ErrSavedQueryExists
// when a row with the same (name, env) already exists — the DB unique
// index `idx_saved_query_name_env` is the authoritative gate, so the
// handler does not need to win the SavedExists race anymore.
func (q *Queries) CreateSaved(name, query, creator string, envid uint) error {
	saved := SavedQuery{
		Name:          name,
		Query:         query,
		Creator:       creator,
		EnvironmentID: envid,
	}
	if err := q.DB.Create(&saved).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrSavedQueryExists
		}
		// PG / MySQL drivers may bubble up the driver-specific dup-key
		// error rather than gorm.ErrDuplicatedKey on some versions —
		// fall back to a string match for the well-known sentinels so
		// the handler still gets a clean 409 path.
		es := err.Error()
		if strings.Contains(es, "duplicate key") || strings.Contains(es, "Duplicate entry") || strings.Contains(es, "UNIQUE constraint") {
			return ErrSavedQueryExists
		}
		return err
	}
	return nil
}

// UpdateSaved updates the SQL body of an existing saved query identified by
// (name, env). The creator field is not modified — original ownership stays.
// Returns gorm.ErrRecordNotFound when the row does not exist.
func (q *Queries) UpdateSaved(name, query string, envid uint) error {
	saved, err := q.GetSavedByEnv(name, envid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return fmt.Errorf("error getting saved query %w", err)
	}
	if err := q.DB.Model(&saved).Update("query", query).Error; err != nil {
		return fmt.Errorf("in Updates %w", err)
	}
	return nil
}

// DeleteSavedByEnv removes a saved query by name within an environment.
// Returns gorm.ErrRecordNotFound when nothing matched.
func (q *Queries) DeleteSavedByEnv(name string, envid uint) error {
	saved, err := q.GetSavedByEnv(name, envid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return fmt.Errorf("error getting saved query %w", err)
	}
	if err := q.DB.Unscoped().Delete(&saved).Error; err != nil {
		return fmt.Errorf("in DeleteSaved %w", err)
	}
	return nil
}

// DeleteSaved removes a saved query owned by (creator, env, name).
// Retained for backward compatibility with non-API callers.
func (q *Queries) DeleteSaved(name, creator string, envid uint) error {
	saved, err := q.GetSaved(name, creator, envid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return fmt.Errorf("error getting saved query %w", err)
	}
	if err := q.DB.Unscoped().Delete(&saved).Error; err != nil {
		return fmt.Errorf("in DeleteSaved %w", err)
	}
	return nil
}
