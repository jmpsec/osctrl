package environments

import (
	"bytes"
	"text/template"
)

// QuickAddOneLiner generic to generate quick add one-liners
func QuickAddOneLiner(oneliner string, environment TLSEnvironment, target string) (string, error) {
	t, err := template.New(target).Parse(oneliner)
	if err != nil {
		return "", err
	}
	data := struct {
		TLSHost     string
		Environment string
		SecretPath  string
	}{
		TLSHost:     environment.Hostname,
		Environment: environment.Name,
		SecretPath:  environment.EnrollSecretPath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// QuickRemoveOneLiner generic to generate quick remove one-liners
func QuickRemoveOneLiner(oneliner string, environment TLSEnvironment, target string) (string, error) {
	t, err := template.New(target).Parse(oneliner)
	if err != nil {
		return "", err
	}
	data := struct {
		TLSHost     string
		Environment string
		SecretPath  string
	}{
		TLSHost:     environment.Hostname,
		Environment: environment.Name,
		SecretPath:  environment.RemoveSecretPath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// QuickAddOneLinerShell to get the quick add one-liner for Linux/OSX nodes
func QuickAddOneLinerShell(environment TLSEnvironment) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.sh | sh`
	return QuickAddOneLiner(s, environment, "enroll.sh")
}

// QuickRemoveOneLinerShell to get the quick remove one-liner for Linux/OSX nodes
func QuickRemoveOneLinerShell(environment TLSEnvironment) (string, error) {
	s := `curl -sk https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.sh | sh`
	return QuickRemoveOneLiner(s, environment, "remove.sh")
}

// QuickAddOneLinerPowershell to get the quick add one-liner for Windows nodes
func QuickAddOneLinerPowershell(environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/enroll.ps1'))`
	return QuickAddOneLiner(s, environment, "enroll.ps1")
}

// QuickRemoveOneLinerPowershell to get the quick remove one-liner for Windows nodes
func QuickRemoveOneLinerPowershell(environment TLSEnvironment) (string, error) {
	s := `Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
iex ((New-Object System.Net.WebClient).DownloadString('https://{{ .TLSHost }}/{{ .Environment }}/{{ .SecretPath }}/remove.ps1'))`
	return QuickRemoveOneLiner(s, environment, "remove.ps1")
}

// QuickAddScript to get a quick add script for a environment
func QuickAddScript(project, script string, environment TLSEnvironment) (string, error) {
	var templateName, templatePath string
	// What script is it?
	switch script {
	case "enroll.sh":
		templateName = "quick-add.sh"
		templatePath = "scripts/quick-add.sh"
	case "enroll.ps1":
		templateName = "quick-add.ps1"
		templatePath = "scripts/quick-add.ps1"
	case "remove.sh":
		templateName = "quick-remove.sh"
		templatePath = "scripts/quick-remove.sh"
	case "remove.ps1":
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
