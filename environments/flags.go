package environments

import (
	"bytes"
	"fmt"
	"text/template"
)

const (
	// FlagTLSServerCerts for the --tls_server_certs flag
	FlagTLSServerCerts string = `--tls_server_certs={{ .CertFile }}`
	// FlagsTemplate to generate flags for enrolling nodes
	FlagsTemplate string = `
--host_identifier=uuid
--force=true
--utc=true
--enroll_secret_path={{ .SecretFile }}
--enroll_tls_endpoint=/{{ .Environment.UUID }}/{{ .Environment.EnrollPath }}
--config_plugin=tls
--config_tls_endpoint=/{{ .Environment.UUID }}/{{ .Environment.ConfigPath }}
--config_tls_refresh={{ .Environment.ConfigInterval }}
--config_tls_max_attempts=5
--logger_plugin=tls
--logger_tls_compress=true
--logger_tls_endpoint=/{{ .Environment.UUID }}/{{ .Environment.LogPath }}
--logger_tls_period={{ .Environment.LogInterval }}
--disable_carver=false
--carver_disable_function=false
--carver_start_endpoint=/{{ .Environment.UUID }}/{{ .Environment.CarverInitPath }}
--carver_continue_endpoint=/{{ .Environment.UUID }}/{{ .Environment.CarverBlockPath }}
--disable_distributed=false
--distributed_interval={{ .Environment.QueryInterval }}
--distributed_plugin=tls
--distributed_tls_max_attempts=5
--distributed_tls_read_endpoint=/{{ .Environment.UUID }}/{{ .Environment.QueryReadPath }}
--distributed_tls_write_endpoint=/{{ .Environment.UUID }}/{{ .Environment.QueryWritePath }}
--tls_hostname={{ .Environment.Hostname }}
{{ .FlagServerCerts }}
`
)

const (
	// EmptyFlagSecret to use as placeholder for the secret file
	EmptyFlagSecret string = "__SECRET_FILE__"
	// EmptyFlagCert to use as placeholder for the certificate file
	EmptyFlagCert   string = "__CERT_FILE__"
)

type flagData struct {
	SecretFile      string
	Environment     TLSEnvironment
	FlagServerCerts string
}

// GenerateServerCertsFlag to generate the --tls_server_certs flag
func GenerateServerCertsFlag(certificatePath string) string {
	t, err := template.New("servercerts").Parse(FlagTLSServerCerts)
	if err != nil {
		return ""
	}
	if certificatePath == "" {
		return ""
	}
	data := struct {
		CertFile string
	}{
		CertFile: certificatePath,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return ""
	}
	return tpl.String()
}

// GenerateFlags to generate flags
func GenerateFlags(env TLSEnvironment, secretPath, certPath string) (string, error) {
	t, err := template.New("flags").Parse(FlagsTemplate)
	if err != nil {
		return "", err
	}
	flagSecret := secretPath
	if secretPath == "" {
		flagSecret = EmptyFlagSecret
	}
	certificatePath := certPath
	if certPath == "" {
		certificatePath = EmptyFlagCert
	}
	flagServerCerts := GenerateServerCertsFlag(certificatePath)
	if env.Certificate == "" {
		flagServerCerts = ""
	}
	data := flagData{
		SecretFile:      flagSecret,
		Environment:     env,
		FlagServerCerts: flagServerCerts,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}

// GenerateFlagsEnv to generate flags by environment name
func (environment *Environment) GenerateFlagsEnv(name string, secretPath, certPath string) (string, error) {
	env, err := environment.Get(name)
	if err != nil {
		return "", fmt.Errorf("error getting environment %v", err)
	}
	return GenerateFlags(env, secretPath, certPath)
}
