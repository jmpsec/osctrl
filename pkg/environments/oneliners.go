package environments

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/version"
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
	EnrollTarget = settings.ScriptEnroll
	// RemoveTarget for remove target
	RemoveTarget = settings.ScriptRemove
	// EnrollShell for enroll shell
	EnrollShell = EnrollTarget + ShellTarget
	// RemoveShell for remove shell
	RemoveShell = RemoveTarget + ShellTarget
	// EnrollPowershell for enroll powershell
	EnrollPowershell = EnrollTarget + PowershellTarget
	// RemovePowershell for remove powershell
	RemovePowershell = RemoveTarget + PowershellTarget
	// TemplateAddShell for template name
	TemplateAddShell = "quick-add" + ShellTarget
	// TemplateRemoveShell for template name
	TemplateRemoveShell = "quick-remove" + ShellTarget
	// TemplateAddPowershell for template name
	TemplateAddPowershell = "quick-add" + PowershellTarget
	// TemplateRemovePowershell for template name
	TemplateRemovePowershell = "quick-remove" + PowershellTarget
)

// Valid values for scripts
var validScript = map[string]bool{
	EnrollShell:      true,
	EnrollPowershell: true,
	RemoveShell:      true,
	RemovePowershell: true,
}

// pinnedTLS returns the one-liner fragment that trusts only the certificates
// stored in the environment: the server's leaf must be one of them. It is used
// instead of disabling verification, since the script it fetches is executed.
// curl checks --pinnedpubkey even with -k; the PowerShell callback compares the
// SHA-256 of the presented certificate.
func pinnedTLS(certPEM, target string) (string, error) {
	var spki, raw []string
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parsing environment certificate: %w", err)
		}
		k := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		spki = append(spki, "sha256//"+base64.StdEncoding.EncodeToString(k[:]))
		c := sha256.Sum256(cert.Raw)
		raw = append(raw, "'"+strings.ToUpper(hex.EncodeToString(c[:]))+"'")
	}
	if len(spki) == 0 {
		return "", errors.New("environment certificate has no PEM certificate")
	}
	if strings.HasSuffix(target, ShellTarget) {
		return InsecureShellTLS + " --pinnedpubkey '" + strings.Join(spki, ";") + "'", nil
	}
	return "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {param($s,$c) @(" + strings.Join(raw, ",") +
		") -contains ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetRawCertData())) -replace '-','')};", nil
}

// PrepareOneLiner generic to generate  one-liners. insecure disables server
// verification and must only come from an explicit operator opt-in; an
// environment certificate is pinned instead.
func PrepareOneLiner(oneliner string, insecure bool, environment TLSEnvironment, target string) (string, error) {
	insecureTLS := ""
	if insecure {
		if strings.HasSuffix(target, ShellTarget) {
			insecureTLS = InsecureShellTLS
		} else if strings.HasSuffix(target, PowershellTarget) {
			insecureTLS = InsecurePowershellTLS
		}
	} else if environment.Certificate != "" && (strings.HasSuffix(target, ShellTarget) || strings.HasSuffix(target, PowershellTarget)) {
		var err error
		if insecureTLS, err = pinnedTLS(environment.Certificate, target); err != nil {
			return "", err
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
func QuickAddOneLinerShell(insecure bool, environment TLSEnvironment) (string, error) {
	s := `curl -s{{ .InsecureTLS }} https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.sh | sh`
	return PrepareOneLiner(s, insecure, environment, EnrollShell)
}

// QuickRemoveOneLinerShell to get the quick remove one-liner for Linux/OSX nodes
func QuickRemoveOneLinerShell(insecure bool, environment TLSEnvironment) (string, error) {
	s := `curl -s{{ .InsecureTLS }} https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.sh | sh`
	return PrepareOneLiner(s, insecure, environment, RemoveShell)
}

// QuickAddOneLinerPowershell to get the quick add one-liner for Windows nodes
func QuickAddOneLinerPowershell(insecure bool, environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
{{ .InsecureTLS }}
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.ps1'))`
	return PrepareOneLiner(s, insecure, environment, EnrollPowershell)
}

// QuickRemoveOneLinerPowershell to get the quick remove one-liner for Windows nodes
func QuickRemoveOneLinerPowershell(insecure bool, environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
{{ .InsecureTLS }}
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.ps1'))`
	return PrepareOneLiner(s, insecure, environment, RemovePowershell)
}

// QuickAddScript to get a quick add script for a environment
func QuickAddScript(project, script string, environment TLSEnvironment) (string, error) {
	if !validScript[script] {
		return "", fmt.Errorf("invalid script - %s", script)
	}
	var templateName, templateScript string
	// What script is it?
	switch script {
	case EnrollShell:
		templateName = TemplateAddShell
		templateScript = QuickAddScriptShell
	case EnrollPowershell:
		templateName = TemplateAddPowershell
		templateScript = QuickAddScriptPowershell
	case RemoveShell:
		templateName = TemplateRemoveShell
		templateScript = QuickRemoveScriptShell
	case RemovePowershell:
		templateName = TemplateRemovePowershell
		templateScript = QuickRemoveScriptPowershell
	}
	// Prepare template
	t, err := template.New(templateName).Parse(templateScript)
	if err != nil {
		return "", err
	}
	// Prepare template data
	data := struct {
		Project        string
		OsqueryVersion string
		Environment    TLSEnvironment
	}{
		Project:        project,
		OsqueryVersion: version.OsqueryVersion,
		Environment:    environment,
	}
	// Compile template into buffer
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}
