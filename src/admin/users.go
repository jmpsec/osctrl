package main

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
func checkLoginCredentials(username, password string) (bool, AdminUser) {
	// Retrieve user
	user, err := getUser(username)
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
func getUser(username string) (AdminUser, error) {
	var user AdminUser
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Create new user
func createUser(user AdminUser) error {
	if db.NewRecord(user) {
		if err := db.Create(&user).Error; err != nil {
			return fmt.Errorf("Create AdminUser %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// New empty user
func newUser(username, password, fullname string, admin bool) (AdminUser, error) {
	if !userExists(username) {
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

// Check if user exists
func userExists(username string) bool {
	var results int
	db.Model(&AdminUser{}).Where("username = ?", username).Count(&results)
	return (results > 0)
}

// Get all users
func getAllUsers() ([]AdminUser, error) {
	var users []AdminUser
	if err := db.Find(&users).Error; err != nil {
		return users, err
	}
	return users, nil
}

// Delete user by username
func deleteUser(username string) error {
	user, err := getUser(username)
	if err != nil {
		return fmt.Errorf("getUser %v", err)
	}
	if err := db.Delete(&user).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}
