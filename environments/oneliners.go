package environments

import (
	"bytes"
	"strings"
	"text/template"
)

const (
	// InsecureShellTLS for insecure TLS connections in shell oneliners
	InsecureShellTLS = "k"
	// InsecurePowershellTLS for insecure TLS connections in powershell onliners
	InsecurePowershellTLS = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"
)

const (
	// ShellTarget for shell extension
	ShellTarget = ".sh"
	// PowershellTarget for powershell extension
	PowershellTarget = ".ps1"
	// EnrollTarget for enroll target
	EnrollTarget = "enroll"
	// RemoveTarget for remove target
	RemoveTarget = "remove"
	// EnrollShell for enroll shell
	EnrollShell = EnrollTarget + ShellTarget
	// RemoveShell for remove shell
	RemoveShell = RemoveTarget + ShellTarget
	// EnrollPowershell for enroll powershell
	EnrollPowershell = EnrollTarget + PowershellTarget
	// RemovePowershell for remove powershell
	RemovePowershell = RemoveTarget + PowershellTarget
)

// PrepareOneLiner generic to generate  one-liners
func PrepareOneLiner(oneliner string, environment TLSEnvironment, target string) (string, error) {
	// Determine if insecure TLS is on
	insecureTLS := ""
	if environment.Certificate != "" {
		if strings.HasSuffix(target, ShellTarget) {
			insecureTLS = InsecureShellTLS
		} else if strings.HasSuffix(target, PowershellTarget) {
			insecureTLS = InsecurePowershellTLS
		}
	}
	// Determine if this is to enroll or remove
	secretPath := environment.RemoveSecretPath
	if strings.HasPrefix(target, EnrollTarget) {
		secretPath = environment.EnrollSecretPath
	}
	// Prepare template for oneliner
	t, err := template.New(target).Parse(oneliner)
	if err != nil {
		return "", err
	}
	data := struct {
		TLSHost     string
		Environment string
		SecretPath  string
		InsecureTLS string
	}{
		TLSHost:     environment.Hostname,
		Environment: environment.UUID,
		SecretPath:  secretPath,
		InsecureTLS: insecureTLS,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// QuickAddOneLinerShell to get the quick add one-liner for Linux/OSX nodes
func QuickAddOneLinerShell(environment TLSEnvironment) (string, error) {
	s := `curl -s{{ .InsecureTLS }} https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.sh | sh`
	return PrepareOneLiner(s, environment, EnrollShell)
}

// QuickRemoveOneLinerShell to get the quick remove one-liner for Linux/OSX nodes
func QuickRemoveOneLinerShell(environment TLSEnvironment) (string, error) {
	s := `curl -s{{ .InsecureTLS }} https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.sh | sh`
	return PrepareOneLiner(s, environment, RemoveShell)
}

// QuickAddOneLinerPowershell to get the quick add one-liner for Windows nodes
func QuickAddOneLinerPowershell(environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
{{ .InsecureTLS }}
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.ps1'))`
	return PrepareOneLiner(s, environment, EnrollPowershell)
}

// QuickRemoveOneLinerPowershell to get the quick remove one-liner for Windows nodes
func QuickRemoveOneLinerPowershell(environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
{{ .InsecureTLS }}
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.ps1'))`
	return PrepareOneLiner(s, environment, RemovePowershell)
}

// QuickAddScript to get a quick add script for a environment
func QuickAddScript(project, script string, environment TLSEnvironment) (string, error) {
	var templateName, templatePath string
	// What script is it?
	switch script {
	case EnrollShell:
		templateName = "quick-add.sh"
		templatePath = "scripts/quick-add.sh"
	case EnrollPowershell:
		templateName = "quick-add.ps1"
		templatePath = "scripts/quick-add.ps1"
	case RemoveShell:
		templateName = "quick-remove.sh"
		templatePath = "scripts/quick-remove.sh"
	case RemovePowershell:
		templateName = "quick-remove.ps1"
		templatePath = "scripts/quick-remove.ps1"
	}
	// Prepare template
	t, err := template.New(templateName).ParseFiles(templatePath)
	if err != nil {
		return "", err
	}
	// Prepare template data
	data := struct {
		Project     string
		Environment TLSEnvironment
	}{
		Project:     project,
		Environment: environment,
	}
	// Compile template into buffer
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}
