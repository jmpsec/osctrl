package queries

import (
	"fmt"

	"gorm.io/gorm"
)

// SavedQuery as abstraction of a saved query to be used in distributed, schedule or packs
type SavedQuery struct {
	gorm.Model
	Name          string
	Creator       string
	Query         string
	EnvironmentID uint
	ExtraData     string
}

// GetSavedByCreator to get a saved query by creator
func (q *Queries) GetSavedByCreator(creator string, envid uint) ([]SavedQuery, error) {
	var saved []SavedQuery
	if err := q.DB.Where("creator = ? AND environment_id = ?", creator, envid).Find(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// GetSaved to get a saved query by creator
func (q *Queries) GetSaved(name, creator string, envid uint) (SavedQuery, error) {
	var saved SavedQuery
	if err := q.DB.Where("creator = ? AND name = ? AND environment_id = ?", creator, name, envid).Find(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// CreateSaved to create new saved query
func (q *Queries) CreateSaved(name, query, creator string, envid uint) error {
	saved := SavedQuery{
		Name:          name,
		Query:         query,
		Creator:       creator,
		EnvironmentID: envid,
	}
	if err := q.DB.Create(&saved).Error; err != nil {
		return err
	}
	return nil
}

// UpdateSaved to update an existing saved query
func (q *Queries) UpdateSaved(name, query, creator string, envid uint) error {
	saved, err := q.GetSaved(name, creator, envid)
	if err != nil {
		return fmt.Errorf("error getting saved query %w", err)
	}
	data := SavedQuery{
		Name:          name,
		Query:         query,
		EnvironmentID: envid,
	}
	if err := q.DB.Model(&saved).Updates(data).Error; err != nil {
		return fmt.Errorf("in Updates %w", err)
	}
	return nil
}

// DeleteSaved to delete an existing saved query
func (q *Queries) DeleteSaved(name, creator string, envid uint) error {
	saved, err := q.GetSaved(name, creator, envid)
	if err != nil {
		return fmt.Errorf("error getting saved query %w", err)
	}
	if err := q.DB.Unscoped().Delete(&saved).Error; err != nil {
		return fmt.Errorf("in DeleteSaved %w", err)
	}
	return nil
}
