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

// AdminTagForNode to check if this tag is used for an specific node
type AdminTagForNode struct {
	Tag    AdminTag
	Tagged bool
}

// TaggedNode to hold tagged nodes
type TaggedNode struct {
	gorm.Model
	Tag    string
	NodeID uint
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
	// table tagged_nodes
	if err := backend.AutoMigrate(TaggedNode{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (tagged_nodes): %v", err)
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
	if !m.Exists(name) {
		return fmt.Errorf("tag does not exist")
	}
	if m.IsTagged(name, node) {
		return fmt.Errorf("node already tagged")
	}
	tagged := TaggedNode{
		Tag:    name,
		NodeID: node.ID,
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

// IsTagged to check if a node is already tagged
func (m *TagManager) IsTagged(name string, node nodes.OsqueryNode) bool {
	var results int
	m.DB.Model(&TaggedNode{}).Where("tag = ? AND node_id = ?", name, node.ID).Count(&results)
	return (results > 0)
}

// UntagNode to untag a node
func (m *TagManager) UntagNode(name string, node nodes.OsqueryNode) error {
	if !m.Exists(name) {
		return fmt.Errorf("tag does not exist")
	}
	var tagged TaggedNode
	if err := m.DB.Where("tag = ? AND node_id = ?", name, node.ID).First(&tagged).Error; err != nil {
		return fmt.Errorf("TaggedNode %v", err)
	}
	if err := m.DB.Unscoped().Delete(&tagged).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// GetTags to retrieve the tags of a given node
func (m *TagManager) GetTags(node nodes.OsqueryNode) ([]AdminTag, error) {
	var tags []AdminTag
	var tagged []TaggedNode
	if err := m.DB.Where("node_id = ?", node.ID).Find(&tagged).Error; err != nil {
		return tags, err
	}
	for _, t := range tagged {
		tag, err := m.Get(t.Tag)
		if err != nil {
			return tags, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// GetNodeTags to decorate tags for a given node
func (m *TagManager) GetNodeTags(tagged  []AdminTag) ([]AdminTagForNode, error) {
	var tags []AdminTag
	var forNode []AdminTagForNode
	tags, err := m.All()
	if err != nil {
		return forNode, err
	}
	for _, t := range tags {
		ttt := false
		for _, _t := range tagged {
			if _t.Name == t.Name {
				ttt = true
				break
			}
		}
		forNode = append(forNode, AdminTagForNode{Tag: t, Tagged: ttt})
	}
	return forNode, nil
}
