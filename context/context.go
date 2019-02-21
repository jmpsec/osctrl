package context

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

// TLSContext to hold each of the TLS context
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

// Context keeps all TLS Contexts
type Context struct {
	DB *gorm.DB
}

// Helper generic to generate quick one-liners
func quickOneLiner(oneliner string, context TLSContext, target string) (string, error) {
	t, err := template.New(target).Parse(oneliner)
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
	s := `curl -sk https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/enroll.sh | sh`
	return quickOneLiner(s, context, "enroll.sh")
}

// Helper to get the quick remove one-liner for Linux/OSX nodes
func quickRemoveOneLinerShell(context TLSContext) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/remove.sh | sh`
	return quickOneLiner(s, context, "remove.sh")
}

// Helper to get the quick add one-liner for Windows nodes
func quickAddOneLinerPowershell(context TLSContext) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/enroll.ps1'))`
	return quickOneLiner(s, context, "enroll.ps1")
}

// Helper to get the quick remove one-liner for Windows nodes
func quickRemoveOneLinerPowershell(context TLSContext) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/remove.ps1'))`
	return quickOneLiner(s, context, "remove.ps1")
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
func (context *Context) readExternalFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

// Helper to get a quick add script for a context
func quickAddScript(project, script string, context TLSContext, paths TLSPath) (string, error) {
	var templateName, templatePath string
	// What script is it?
	if script == "enroll.sh" {
		templateName = "quick-add.sh"
		templatePath = "tmpl_tls/scripts/quick-add.sh"
	} else if script == "enroll.ps1" {
		templateName = "quick-add.ps1"
		templatePath = "tmpl_tls/scripts/quick-add.ps1"
	} else if script == "remove.sh" {
		templateName = "quick-remove.sh"
		templatePath = "tmpl_tls/scripts/quick-remove.sh"
	} else if script == "remove.ps1" {
		templateName = "quick-remove.ps1"
		templatePath = "tmpl_tls/scripts/quick-remove.ps1"
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
		Project: project,
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

// Get TLSContext by name
func (context *Context) Get(name string) (TLSContext, error) {
	var ctx TLSContext
	if err := context.DB.Where("name = ?", name).First(&ctx).Error; err != nil {
		return ctx, err
	}
	return ctx, nil
}

// Empty generates an empty TLSContext with default values
func (context *Context) Empty(name, hostname string) TLSContext {
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

// Create new TLSContext
func (context *Context) Create(ctx TLSContext) error {
	if context.DB.NewRecord(ctx) {
		if err := context.DB.Create(&ctx).Error; err != nil {
			return fmt.Errorf("Create TLSContext %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Exists checks if TLSContext exists already
func (context *Context) Exists(name string) bool {
	var results int
	context.DB.Model(&TLSContext{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// All gets all TLSContext
func (context *Context) All() ([]TLSContext, error) {
	var ctxs []TLSContext
	if err := context.DB.Find(&ctxs).Error; err != nil {
		return ctxs, err
	}
	return ctxs, nil
}

// Delete TLSContext by name
func (context *Context) Delete(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Delete(&ctx).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// UpdateConfiguration configuration for a context
func (context *Context) UpdateConfiguration(name, configuration string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Update("configuration", configuration).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}
