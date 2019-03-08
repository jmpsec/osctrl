package context

import (
	"bytes"
	"text/template"
)

// QuickAddOneLiner generic to generate quick add one-liners
func QuickAddOneLiner(oneliner string, context TLSContext, target string) (string, error) {
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
		SecretPath: context.EnrollSecretPath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// QuickRemoveOneLiner generic to generate quick remove one-liners
func QuickRemoveOneLiner(oneliner string, context TLSContext, target string) (string, error) {
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
		SecretPath: context.RemoveSecretPath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// QuickAddOneLinerShell to get the quick add one-liner for Linux/OSX nodes
func QuickAddOneLinerShell(context TLSContext) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/enroll.sh | sh`
	return QuickAddOneLiner(s, context, "enroll.sh")
}

// QuickRemoveOneLinerShell to get the quick remove one-liner for Linux/OSX nodes
func QuickRemoveOneLinerShell(context TLSContext) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/remove.sh | sh`
	return QuickRemoveOneLiner(s, context, "remove.sh")
}

// QuickAddOneLinerPowershell to get the quick add one-liner for Windows nodes
func QuickAddOneLinerPowershell(context TLSContext) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/enroll.ps1'))`
	return QuickAddOneLiner(s, context, "enroll.ps1")
}

// QuickRemoveOneLinerPowershell to get the quick remove one-liner for Windows nodes
func QuickRemoveOneLinerPowershell(context TLSContext) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Context }}/{{ .SecretPath }}/remove.ps1'))`
	return QuickRemoveOneLiner(s, context, "remove.ps1")
}

// QuickAddScript to get a quick add script for a context
func QuickAddScript(project, script string, context TLSContext, paths TLSPath) (string, error) {
	var templateName, templatePath string
	// What script is it?
	switch script {
	case "enroll.sh":
		templateName = "quick-add.sh"
		templatePath = "tmpl_tls/scripts/quick-add.sh"
	case "enroll.ps1":
		templateName = "quick-add.ps1"
		templatePath = "tmpl_tls/scripts/quick-add.ps1"
	case "remove.sh":
		templateName = "quick-remove.sh"
		templatePath = "tmpl_tls/scripts/quick-remove.sh"
	case "remove.ps1":
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
