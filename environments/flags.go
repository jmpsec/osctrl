package environments

import (
	"bytes"
	"fmt"
	"text/template"
)

const (
	// CarverBlockSizeValue to configure size in bytes for carver blocks
	CarverBlockSizeValue string = "5120000"
	// FlagTLSServerCerts for the --tls_server_certs flag
	FlagTLSServerCerts string = `--tls_server_certs={{ .CertFile }}`
	// FlagCarverBlockSize for the --carver_block_size flag
	FlagCarverBlockSize string = `--carver_block_size={{ .BlockSize }}`
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
{{ .FlagCarverBlock }}
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
	EmptyFlagCert string = "__CERT_FILE__"
)

type flagData struct {
	SecretFile      string
	Environment     TLSEnvironment
	FlagServerCerts string
	FlagCarverBlock string
}

// GenServerCertsFlag to generate the --tls_server_certs flag
func GenServerCertsFlag(certificatePath string) string {
	if certificatePath == "" {
		return ""
	}
	data := struct {
		CertFile string
	}{
		CertFile: certificatePath,
	}
	return GenGenericFlag("servercerts", FlagTLSServerCerts, data)
}

// GenCarveBlockSizeFlag to generate the --carver_block_size flag
func GenCarveBlockSizeFlag(blockSize string) string {
	data := struct {
		BlockSize string
	}{
		BlockSize: blockSize,
	}
	return GenGenericFlag("blocksize", FlagCarverBlockSize, data)
}

// GenGenericFlag to generate a generic flag to be used by osquery
func GenGenericFlag(flagName, flagConst string, data interface{}) string {
	t, err := template.New(flagName).Parse(flagConst)
	if err != nil {
		return ""
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return ""
	}
	return tpl.String()
}

// GenerateFlags to generate flags
func GenerateFlags(env TLSEnvironment, secretPath, certPath string) (string, error) {
	flagSecret := secretPath
	if secretPath == "" {
		flagSecret = EmptyFlagSecret
	}
	certificatePath := certPath
	if certPath == "" {
		certificatePath = EmptyFlagCert
	}
	flagServerCerts := GenServerCertsFlag(certificatePath)
	if env.Certificate == "" {
		flagServerCerts = ""
	}
	data := flagData{
		SecretFile:      flagSecret,
		Environment:     env,
		FlagServerCerts: flagServerCerts,
		FlagCarverBlock: GenCarveBlockSizeFlag(CarverBlockSizeValue),
	}
	return GenGenericFlag("flags", FlagsTemplate, data), nil
}

// GenerateFlagsEnv to generate flags by environment name
func (environment *Environment) GenerateFlagsEnv(idEnv string, secretPath, certPath string) (string, error) {
	env, err := environment.Get(idEnv)
	if err != nil {
		return "", fmt.Errorf("error getting environment %v", err)
	}
	return GenerateFlags(env, secretPath, certPath)
}
