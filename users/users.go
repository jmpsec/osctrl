package users

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// AdminUser to hold all users
type AdminUser struct {
	gorm.Model
	Username  string `gorm:"index"`
	Fullname  string
	PassHash  string
	Admin     bool
	CSRF      string
	Cookie    string
	IPAddress string
	UserAgent string
}

// UserManager have all users of the system
type UserManager struct {
	db    *gorm.DB
	Users []AdminUser
}

// Helper to hash a password before store it
func hashMyPasswordWithSalt(password string) (string, error) {
	saltedBytes := []byte(password)
	hashedBytes, err := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	hash := string(hashedBytes[:])
	return hash, nil
}

// Helper to check provided login credentials by matching hashes
func (m *UserManager) checkLoginCredentials(username, password string) (bool, AdminUser) {
	// Retrieve user
	user, err := m.Get(username)
	if err != nil {
		return false, AdminUser{}
	}
	// Check for hash matching
	p := []byte(password)
	existing := []byte(user.PassHash)
	err = bcrypt.CompareHashAndPassword(existing, p)
	if err != nil {
		return false, AdminUser{}
	}
	return true, user
}

// Get user by username
func (m *UserManager) Get(username string) (AdminUser, error) {
	var user AdminUser
	if err := m.db.Where("username = ?", username).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Create new user
func (m *UserManager) Create(user AdminUser) error {
	if m.db.NewRecord(user) {
		if err := m.db.Create(&user).Error; err != nil {
			return fmt.Errorf("Create AdminUser %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// New empty user
func (m *UserManager) New(username, password, fullname string, admin bool) (AdminUser, error) {
	if !m.Exists(username) {
		passhash, err := hashMyPasswordWithSalt(password)
		if err != nil {
			return AdminUser{}, err
		}
		return AdminUser{
			Username: username,
			PassHash: passhash,
			Admin:    admin,
			Fullname: fullname,
		}, nil
	}
	return AdminUser{}, fmt.Errorf("%s already exists", username)
}

// Exists checks if user exists
func (m *UserManager) Exists(username string) bool {
	var results int
	m.db.Model(&AdminUser{}).Where("username = ?", username).Count(&results)
	return (results > 0)
}

// All get all users
func (m *UserManager) All() ([]AdminUser, error) {
	var users []AdminUser
	if err := m.db.Find(&users).Error; err != nil {
		return users, err
	}
	return users, nil
}

// Delete user by username
func (m *UserManager) Delete(username string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %v", err)
	}
	if err := m.db.Delete(&user).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}
