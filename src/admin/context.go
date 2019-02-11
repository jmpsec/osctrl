package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"text/template"

	"github.com/jinzhu/gorm"
	"github.com/segmentio/ksuid"
)

const (
	defaultEnrollPath      = "enroll"
	defaultLogPath         = "log"
	defaultConfigPath      = "config"
	defaultQueryReadPath   = "read"
	defaultQueryWritePath  = "write"
	defaultCarverInitPath  = "init"
	defaultCarverBlockPath = "block"
	defaultContextIcon     = "fas fa-wrench"
	defaultContextType     = "osquery"
	defaultSecretLength    = 64
	errorRandomString      = "SomethingRandomWentWrong"
)

// TLSContext to hold all the TLS contexts
type TLSContext struct {
	gorm.Model
	Name          string `gorm:"index"`
	Hostname      string
	Secret        string
	SecretPath    string
	Type          string
	DebugHTTP     bool
	Icon          string
	Configuration string
	Certificate   string
}

// TLSPath to hold all the paths for TLS
type TLSPath struct {
	EnrollPath      string
	LogPath         string
	ConfigPath      string
	QueryReadPath   string
	QueryWritePath  string
	CarverInitPath  string
	CarverBlockPath string
}

// Helper generic to generate quick add one-liners
func quickAddOneLiner(oneliner string, context TLSContext) (string, error) {
	t, err := template.New("QuickAddOneLiner").Parse(oneliner)
	if err != nil {
		return "", err
	}
	data := struct {
		TLSHost    string
		Context    string
		SecretPath string
	}{
		TLSHost:    context.Hostname,
		Context:    context.Name,
		SecretPath: context.SecretPath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// Helper to get the quick add one-liner for Linux/OSX nodes
func quickAddOneLinerShell(context TLSContext) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/osctrl.sh | sh`
	return quickAddOneLiner(s, context)
}

// Helper to get the quick add one-liner for Windows nodes
func quickAddOneLinerPowershell(context TLSContext) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/osctrl.ps1'))`
	return quickAddOneLiner(s, context)
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

// Helper to read an external file and return contents
func readExternalFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

// Helper to get a quick add script for a context
func quickAddScript(script string, context TLSContext, paths TLSPath) (string, error) {
	var templateName, templatePath string
	// What script is it?
	if script == "osctrl.sh" {
		templateName = "quick-add.sh"
		templatePath = "tmpl_tls/scripts/quick-add.sh"
	} else if script == "osctrl.ps1" {
		templateName = "quick-add.ps1"
		templatePath = "tmpl_tls/scripts/quick-add.ps1"
	}
	// Prepare template
	t, err := template.New(templateName).ParseFiles(templatePath)
	if err != nil {
		return "", err
	}
	// Prepare template data
	data := struct {
		Project string
		Context TLSContext
		Path    TLSPath
	}{
		Project: appName,
		Context: context,
		Path:    paths,
	}
	// Compile template into buffer
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
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
func emptyContext(name, hostname string) TLSContext {
	return TLSContext{
		Name:          name,
		Hostname:      hostname,
		Secret:        generateRandomString(defaultSecretLength),
		SecretPath:    generateKSUID(),
		Type:          defaultContextType,
		DebugHTTP:     false,
		Icon:          defaultContextIcon,
		Configuration: "",
		Certificate:   "",
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

// Update configuration for a context
func updateConfiguration(name, configuration string) error {
	ctx, err := getContext(name)
	if err != nil {
		return fmt.Errorf("getContext %v", err)
	}
	if err := db.Model(&ctx).Update("configuration", configuration).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}
