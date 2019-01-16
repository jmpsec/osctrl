package main

import "github.com/jinzhu/gorm"

// TLSConfiguration to hold all configuration values in the db
type TLSConfiguration struct {
	gorm.Model
	JSONConfigurationTLS
}

// AdminConfiguration to hold all configuration values in the db
type AdminConfiguration struct {
	gorm.Model
	JSONConfigurationAdmin
}
