package tags

import (
	"fmt"
	"strings"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	// DefaultTagIcon as default icon to use for tags
	DefaultTagIcon string = "fas fa-tag"
	// DefaultAutoTagUser as default user ID to be used for auto tagging
	DefaultAutoTagUser uint = 0
	// DefaultAutocreated as default username and description for tags
	DefaultAutocreated = "Autocreated"
	// TagTypeEnv as tag type for environment name
	TagTypeEnv uint = 0
	// TagTypeUUID as tag type for node UUID
	TagTypeUUID uint = 1
	// TagTypePlatform as tag type for node platform
	TagTypePlatform uint = 2
	// TagTypeLocalname as tag type for node localname
	TagTypeLocalname uint = 3
	// TagTypeCustom as tag type for custom tags
	TagTypeCustom uint = 4
	// TagTypeUnknown as tag type for unknown tags
	TagTypeUnknown uint = 5
	// ActionAdd as action to add a tag
	ActionAdd string = "add"
	// ActionEdit as action to edit a tag
	ActionEdit string = "edit"
	// ActionRemove as action to remove a tag
	ActionRemove string = "remove"
)

// AdminTag to hold all tags
type AdminTag struct {
	gorm.Model
	Name          string `gorm:"index"`
	Description   string
	Color         string
	Icon          string
	CreatedBy     string
	AutoTag       bool
	EnvironmentID uint
	TagType       uint
}

// AdminTagForNode to check if this tag is used for an specific node
type AdminTagForNode struct {
	Tag    AdminTag
	Tagged bool
}

// TaggedNode to hold tagged nodes
type TaggedNode struct {
	gorm.Model
	Tag        string
	AdminTagID uint
	NodeID     uint
	AutoTag    bool
	TaggedBy   string
	UserID     uint
}

// TagManager have all tags
type TagManager struct {
	DB *gorm.DB
}

// CreateTagManager to initialize the tags struct and tables
func CreateTagManager(backend *gorm.DB) *TagManager {
	var t *TagManager = &TagManager{DB: backend}
	// table admin_tags
	if err := backend.AutoMigrate(&AdminTag{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (admin_tags): %v", err)
	}
	// table tagged_nodes
	if err := backend.AutoMigrate(&TaggedNode{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (tagged_nodes): %v", err)
	}
	return t
}

// Get tag by name
func (m *TagManager) Get(name string, envID uint) (AdminTag, error) {
	var tag AdminTag
	if name == "" {
		return tag, fmt.Errorf("empty tag")
	}
	if envID == 0 {
		return tag, fmt.Errorf("empty environment")
	}
	if err := m.DB.Where("name = ? AND environment_id = ?", name, envID).First(&tag).Error; err != nil {
		return tag, err
	}
	return tag, nil
}

// Create new tag
func (m *TagManager) Create(tag *AdminTag) error {
	if err := m.DB.Create(&tag).Error; err != nil {
		return fmt.Errorf("Create AdminTag %w", err)
	}
	return nil
}

// New empty tag
func (m *TagManager) New(name, description, color, icon, user string, envID uint, auto bool, tagType uint) (AdminTag, error) {
	tagColor := color
	tagIcon := icon
	if tagColor == "" {
		tagColor = RandomColor()
	}
	if tagIcon == "" {
		tagIcon = DefaultTagIcon
	}
	if !m.Exists(name) {
		return AdminTag{
			Name:          name,
			Description:   description,
			Color:         strings.ToLower(tagColor),
			Icon:          strings.ToLower(tagIcon),
			CreatedBy:     user,
			EnvironmentID: envID,
			AutoTag:       auto,
			TagType:       tagType,
		}, nil
	}
	return AdminTag{}, fmt.Errorf("%s already exists", name)
}

// NewTag to create a tag and creates it without returning it
func (m *TagManager) NewTag(name, description, color, icon, user string, envID uint, auto bool, tagType uint) error {
	tag, err := m.New(name, description, color, icon, user, envID, auto, tagType)
	if err != nil {
		return err
	}
	return m.Create(&tag)
}

// Exists checks if tag exists
func (m *TagManager) Exists(name string) bool {
	var results int64
	m.DB.Model(&AdminTag{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// ExistsByEnv checks if tag exists by environment
func (m *TagManager) ExistsByEnv(name string, envID uint) bool {
	var results int64
	m.DB.Model(&AdminTag{}).Where("name = ? AND environment_id = ?", name, envID).Count(&results)
	return (results > 0)
}

// ExistsGet checks if tag exists and returns the tag
func (m *TagManager) ExistsGet(name string, envID uint) (bool, AdminTag) {
	tag, err := m.Get(name, envID)
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

// All get all tags by environment
func (m *TagManager) GetByEnv(envID uint) ([]AdminTag, error) {
	var tags []AdminTag
	if err := m.DB.Where("environment_id = ?", envID).Find(&tags).Error; err != nil {
		return tags, err
	}
	return tags, nil
}

// DeleteGet tag by name
func (m *TagManager) DeleteGet(name string, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if err := m.DB.Unscoped().Delete(&tag).Error; err != nil {
		return fmt.Errorf("delete %w", err)
	}
	return nil
}

// Delete tag by name
func (m *TagManager) Delete(tag *AdminTag) error {
	if err := m.DB.Unscoped().Delete(tag).Error; err != nil {
		return fmt.Errorf("delete %w", err)
	}
	return nil
}

// ChangeGetDescription to update description for a tag
func (m *TagManager) ChangeGetDescription(name, description string, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if description != tag.Description {
		if err := m.DB.Model(&tag).Update("description", description).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeDescription to update description for a tag
func (m *TagManager) ChangeDescription(tag *AdminTag, desc string) error {
	if desc != tag.Description {
		if err := m.DB.Model(tag).Update("description", desc).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeGetColor to update color for a tag
func (m *TagManager) ChangeGetColor(name, color string, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if color != tag.Color {
		if err := m.DB.Model(&tag).Update("color", color).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeColor to update color for a tag
func (m *TagManager) ChangeColor(tag *AdminTag, color string) error {
	if color != tag.Color {
		if err := m.DB.Model(tag).Update("color", color).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeGetIcon to update icon for a tag
func (m *TagManager) ChangeGetIcon(name, icon string, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if icon != tag.Icon {
		if err := m.DB.Model(&tag).Update("icon", icon).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeIcon to update icon for a tag
func (m *TagManager) ChangeIcon(tag *AdminTag, icon string) error {
	if icon != tag.Icon {
		if err := m.DB.Model(tag).Update("icon", icon).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeGetTagType to update tag type for a tag
func (m *TagManager) ChangeGetTagType(name string, tagType uint, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if tagType != tag.TagType {
		if err := m.DB.Model(&tag).Update("tag_type", tagType).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeTagType to update tag type for a tag
func (m *TagManager) ChangeTagType(tag *AdminTag, tagType uint) error {
	if tagType != tag.TagType {
		if err := m.DB.Model(tag).Update("tag_type", tagType).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeGetEnvironment to update environment for a tag
func (m *TagManager) ChangeGetEnvironment(name string, envID uint) error {
	tag, err := m.Get(name, envID)
	if err != nil {
		return fmt.Errorf("error getting tag %w", err)
	}
	if envID != tag.EnvironmentID {
		if err := m.DB.Model(&tag).Update("environment_id", envID).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeEnvironment to update environment for a tag
func (m *TagManager) ChangeEnvironment(tag *AdminTag, envID uint) error {
	if envID != tag.EnvironmentID {
		if err := m.DB.Model(tag).Update("environment_id", envID).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// AutoTagNode to automatically tag a node based on multiple fields
func (m *TagManager) AutoTagNode(env string, node nodes.OsqueryNode, user string) error {
	l := []string{env, node.UUID, node.Platform, node.Localname}
	return m.TagNodeMulti(l, node, user, true)
}

// TagNodeMulti to tag a node with multiple tags
// TODO use the correct user_id
func (m *TagManager) TagNodeMulti(tags []string, node nodes.OsqueryNode, user string, auto bool) error {
	for i, t := range tags {
		if err := m.TagNode(t, node, user, auto, uint(i)); err != nil {
			return err
		}
	}
	return nil
}

// TagNode to tag a node, tag is created if does not exist
// TODO use the correct user_id
func (m *TagManager) TagNode(name string, node nodes.OsqueryNode, user string, auto bool, tagType uint) error {
	if len(name) == 0 {
		return fmt.Errorf("empty tag")
	}
	check, tag := m.ExistsGet(name, node.EnvironmentID)
	if !check {
		newTag := AdminTag{
			Name:          name,
			Description:   DefaultAutocreated,
			Color:         RandomColor(),
			Icon:          DefaultTagIcon,
			CreatedBy:     user,
			AutoTag:       auto,
			EnvironmentID: node.EnvironmentID,
			TagType:       tagType,
		}
		if err := m.Create(&newTag); err != nil {
			return fmt.Errorf("error creating tag %w", err)
		}
		tag = newTag
	}
	if m.IsTagged(tag.Name, node) {
		return fmt.Errorf("node already tagged")
	}
	tagged := TaggedNode{
		Tag:        tag.Name,
		AdminTagID: tag.ID,
		NodeID:     node.ID,
		AutoTag:    auto,
		UserID:     DefaultAutoTagUser,
		TaggedBy:   user,
	}
	if err := m.DB.Create(&tagged).Error; err != nil {
		return fmt.Errorf("error tagging node %w", err)
	}
	return nil
}

// IsTagged to check if a node is already tagged
func (m *TagManager) IsTagged(name string, node nodes.OsqueryNode) bool {
	return m.IsTaggedID(name, node.ID)
}

// IsTaggedID to check if a node is already tagged by node ID
func (m *TagManager) IsTaggedID(name string, nodeID uint) bool {
	var results int64
	if name == "" {
		return true
	}
	m.DB.Model(&TaggedNode{}).Where("tag = ? AND node_id = ?", name, nodeID).Count(&results)
	return (results > 0)
}

// UntagNode to untag a node
func (m *TagManager) UntagNode(name string, node nodes.OsqueryNode) error {
	if !m.Exists(name) {
		return fmt.Errorf("tag does not exist")
	}
	var tagged TaggedNode
	if err := m.DB.Where("tag = ? AND node_id = ?", name, node.ID).First(&tagged).Error; err != nil {
		return fmt.Errorf("TaggedNode %w", err)
	}
	if err := m.DB.Unscoped().Delete(&tagged).Error; err != nil {
		return fmt.Errorf("Delete %w", err)
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
		if t.Tag == "" {
			continue
		}
		tag, err := m.Get(t.Tag, node.EnvironmentID)
		if err != nil {
			continue
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// GetNodeTags to decorate tags for a given node
func (m *TagManager) GetNodeTags(tagged []AdminTag) ([]AdminTagForNode, error) {
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
