package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"

	"github.com/jinzhu/gorm"
	"github.com/segmentio/ksuid"
)

const (
	defaultEnrollPath      = "osquery_enroll"
	defaultLogPath         = "osquery_log"
	defaultConfigPath      = "osquery_config"
	defaultQueryReadPath   = "osquery_read"
	defaultQueryWritePath  = "osquery_write"
	defaultCarverInitPath  = "carver_init"
	defaultCarverBlockPath = "carver_block"
	defaultContextIcon     = "fas fa-wrench"
	defaultContextType     = "osquery"
	defaultSecretLength    = 64
)

const (
	errorRandomString = "SomethingRandomWentWrong"
)

// Helper to get a quick add script for a context
func quickAddScript(hostname, script string, context TLSContext) (string, error) {
	var templateName, templatePath string
	// What script is it?
	if script == "osctrl.sh" {
		templateName = "osctrl.sh"
		templatePath = "templates/quick-add.sh"
	} else if script == "osctrl.ps1" {
		templateName = "osctrl.ps1"
		templatePath = "templates/quick-add.ps1"
	}
	// Prepare template
	t, err := template.New(templateName).ParseFiles(templatePath)
	if err != nil {
		return "", err
	}
	// Prepare template data
	data := struct {
		Project     string
		TLSHostname string
		Context     TLSContext
	}{
		Project:     appName,
		TLSHostname: hostname,
		Context:     context,
	}
	// Compile template into buffer
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// TLSContext to hold all the TLS contexts
type TLSContext struct {
	gorm.Model
	Name            string `gorm:"index"`
	Secret          string
	SecretPath      string
	Type            string
	DebugHTTP       bool
	Icon            string
	Configuration   string
	Certificate     string
	EnrollPath      string
	LogPath         string
	ConfigPath      string
	QueryReadPath   string
	QueryWritePath  string
	CarverInitPath  string
	CarverBlockPath string
}

// Get context by name
func getContext(name string) (TLSContext, error) {
	var ctx TLSContext
	if err := db.Where("name = ?", name).First(&ctx).Error; err != nil {
		return ctx, err
	}
	return ctx, nil
}

// Generate empty context with default values
func emptyContext(name string) TLSContext {
	return TLSContext{
		Name:            name,
		Secret:          generateRandomString(defaultSecretLength),
		SecretPath:      generateKSUID(),
		Type:            defaultContextType,
		DebugHTTP:       false,
		Icon:            defaultContextIcon,
		Configuration:   "",
		Certificate:     "",
		EnrollPath:      defaultEnrollPath,
		LogPath:         defaultLogPath,
		ConfigPath:      defaultConfigPath,
		QueryReadPath:   defaultQueryReadPath,
		QueryWritePath:  defaultQueryWritePath,
		CarverInitPath:  defaultCarverInitPath,
		CarverBlockPath: defaultCarverBlockPath,
	}
}

// Create new context
func createContext(ctx TLSContext) error {
	if db.NewRecord(ctx) {
		if err := db.Create(&ctx).Error; err != nil {
			return fmt.Errorf("Create TLSContext %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Check if context exists
func contextExists(name string) bool {
	var results int
	db.Model(&TLSContext{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// Get all contexts
func getAllContexts() ([]TLSContext, error) {
	var ctxs []TLSContext
	if err := db.Find(&ctxs).Error; err != nil {
		return ctxs, err
	}
	return ctxs, nil
}

// Delete context by name
func deleteContext(name string) error {
	ctx, err := getContext(name)
	if err != nil {
		return fmt.Errorf("getContext %v", err)
	}
	if err := db.Delete(&ctx).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// Helper to generate a random string of n characters
func generateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return errorRandomString
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Helper to generate a KSUID
// See https://github.com/segmentio/ksuid for more info about KSUIDs
func generateKSUID() string {
	id := ksuid.New()
	return id.String()
}

// Helper to read a configuration file
func readConfigurationFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}
