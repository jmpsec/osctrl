package tags

import (
	"fmt"
	"log"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/jmpsec/osctrl/nodes"
)

const (
	// DefaultTagIcon as default icon to use for tags
	DefaultTagIcon string = "fas fa-tag"
)

// AdminTag to hold all tags
type AdminTag struct {
	gorm.Model
	Name        string `gorm:"index"`
	Description string
	Color       string
	Icon        string
}

// TaggedNode to hold tagged nodes
type TaggedNode struct {
	gorm.Model
	AdminTagID    uint `gorm:"index"`
	Tag           AdminTag
	OsqueryNodeID uint `gorm:"index"`
	Node          nodes.OsqueryNode
}

// TagManager have all tags
type TagManager struct {
	DB *gorm.DB
}

// CreateTagManager to initialize the tags struct and tables
func CreateTagManager(backend *gorm.DB) *TagManager {
	var t *TagManager
	t = &TagManager{DB: backend}
	// table admin_users
	if err := backend.AutoMigrate(AdminTag{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (admin_tags): %v", err)
	}
	return t
}

// Get tag by name
func (m *TagManager) Get(name string) (AdminTag, error) {
	var tag AdminTag
	if err := m.DB.Where("name = ?", name).First(&tag).Error; err != nil {
		return tag, err
	}
	return tag, nil
}

// Create new tag
func (m *TagManager) Create(tag AdminTag) error {
	if m.DB.NewRecord(tag) {
		if err := m.DB.Create(&tag).Error; err != nil {
			return fmt.Errorf("Create AdminTag %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// New empty tag
func (m *TagManager) New(name, description, color, icon string) (AdminTag, error) {
	tagColor := color
	tagIcon := icon
	if tagColor == "" {
		tagColor = randomColor()
	}
	if tagIcon == "" {
		tagIcon = DefaultTagIcon
	}
	if !m.Exists(name) {
		return AdminTag{
			Name:        name,
			Description: description,
			Color:       strings.ToLower(tagColor),
			Icon:        strings.ToLower(tagIcon),
		}, nil
	}
	return AdminTag{}, fmt.Errorf("%s already exists", name)
}

// NewTag to create a tag and creates it without returning it
func (m *TagManager) NewTag(name, description, color, icon string) error {
	tag, err := m.New(name, description, color, icon)
	if err != nil {
		return err
	}
	return m.Create(tag)
}

// Exists checks if tag exists
func (m *TagManager) Exists(name string) bool {
	var results int
	m.DB.Model(&AdminTag{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// ExistsGet checks if tag exists and returns the tag
func (m *TagManager) ExistsGet(name string) (bool, AdminTag) {
	tag, err := m.Get(name)
	if err != nil {
		return false, AdminTag{}
	}
	return true, tag
}

// All get all tags
func (m *TagManager) All() ([]AdminTag, error) {
	var tags []AdminTag
	if err := m.DB.Find(&tags).Error; err != nil {
		return tags, err
	}
	return tags, nil
}

// Delete tag by name
func (m *TagManager) Delete(name string) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	if err := m.DB.Unscoped().Delete(&tag).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// ChangeDescription to update description for a tag
func (m *TagManager) ChangeDescription(name, description string) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	if description != tag.Description {
		if err := m.DB.Model(&tag).Update("description", description).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	return nil
}

// ChangeColor to update color for a tag
func (m *TagManager) ChangeColor(name, color string) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	if color != tag.Color {
		if err := m.DB.Model(&tag).Update("color", color).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	return nil
}

// ChangeIcon to update icon for a tag
func (m *TagManager) ChangeIcon(name, icon string) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	if icon != tag.Icon {
		if err := m.DB.Model(&tag).Update("icon", icon).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	return nil
}

// TagNode to tag a node
func (m *TagManager) TagNode(name string, node nodes.OsqueryNode) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	tagged := TaggedNode{
		AdminTagID:    tag.ID,
		Tag:           tag,
		OsqueryNodeID: node.ID,
		Node:          node,
	}
	if m.DB.NewRecord(tagged) {
		if err := m.DB.Create(&tagged).Error; err != nil {
			return fmt.Errorf("Create TaggedNode %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// UntagNode to untag a node
func (m *TagManager) UntagNode(name string, node nodes.OsqueryNode) error {
	tag, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("error getting tag %v", err)
	}
	tagged := TaggedNode{
		AdminTagID:    tag.ID,
		Tag:           tag,
		OsqueryNodeID: node.ID,
		Node:          node,
	}
	if err := m.DB.Unscoped().Delete(&tagged).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}
