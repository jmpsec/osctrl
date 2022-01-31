package queries

import (
	"fmt"

	"gorm.io/gorm"
)

// SavedQuery as abstraction of a saved query to be used in distributed, schedule or packs
type SavedQuery struct {
	gorm.Model
	Name    string
	Creator string
	Query   string
}

// GetSavedByCreator to get a saved query by creator
func (q *Queries) GetSavedByCreator(creator string) ([]SavedQuery, error) {
	var saved []SavedQuery
	if err := q.DB.Find(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// GetSaved to get a saved query by creator
func (q *Queries) GetSaved(name, creator string) (SavedQuery, error) {
	var saved SavedQuery
	if err := q.DB.Where("creator = ? AND name = ?", creator, name).Find(&saved).Error; err != nil {
		return saved, err
	}
	return saved, nil
}

// CreateSaved to create new saved query
func (q *Queries) CreateSaved(name, query, creator string) error {
	saved := SavedQuery{
		Name:    name,
		Query:   query,
		Creator: creator,
	}
	if err := q.DB.Create(&saved).Error; err != nil {
		return err
	}
	return nil
}

// UpdateSaved to update an existing saved query
func (q *Queries) UpdateSaved(name, query, creator string) error {
	saved, err := q.GetSaved(name, creator)
	if err != nil {
		return fmt.Errorf("error getting saved query %v", err)
	}
	data := SavedQuery{
		Name:  name,
		Query: query,
	}
	if err := q.DB.Model(&saved).Updates(data).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// DeleteSaved to delete an existing saved query
func (q *Queries) DeleteSaved(name, creator string) error {
	saved, err := q.GetSaved(name, creator)
	if err != nil {
		return fmt.Errorf("error getting saved query %v", err)
	}
	if err := q.DB.Unscoped().Delete(&saved).Error; err != nil {
		return fmt.Errorf("DeleteSaved %v", err)
	}
	return nil
}
