package main

import (
	"fmt"

	"github.com/jinzhu/gorm"
)

// AdminUser to hold all users
type AdminUser struct {
	gorm.Model
	Username  string `gorm:"index"`
	Fullname  string
	Password  string
	Admin     bool
	CSRF      string
	Cookie    string
	IPAddress string
	UserAgent string
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
