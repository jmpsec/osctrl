package environments

import (
	"bytes"
	"fmt"
	"text/template"
)

const (
	// CarverBlockSizeValue to configure size in bytes for carver blocks
	CarverBlockSizeValue string = "5120000"
	// FlagGenericValue to use as generator for generic flags
	FlagGenericValue string = `--{{ .FlagName }}={{ .FlagValue }}`
	// FlagTLSServerCerts for the --tls_server_certs flag
	FlagNameTLSServerCerts string = `tls_server_certs`
	// FlagCarverBlockSize for the --carver_block_size flag
	FlagNameCarverBlockSize string = `carver_block_size`
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
	return GenSingleFlag("servercerts", FlagNameTLSServerCerts, certificatePath)
}

// GenCarveBlockSizeFlag to generate the --carver_block_size flag
func GenCarveBlockSizeFlag(blockSize string) string {
	if blockSize == "" {
		return ""
	}
	return GenSingleFlag("blocksize", FlagNameCarverBlockSize, blockSize)
}

// GenSingleFlag to generate a generic flag to be used by osquery
func GenSingleFlag(tmplName, flagName, flagValue string) string {
	data := struct {
		FlagName  string
		FlagValue string
	}{
		FlagName:  flagName,
		FlagValue: flagValue,
	}
	return ParseFlagTemplate(tmplName, FlagGenericValue, data)
}

// ParseFlagTemplate to parse a flag template
func ParseFlagTemplate(tmplName, flagTemplate string, data interface{}) string {
	t, err := template.New(tmplName).Parse(flagTemplate)
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
func (environment *Environment) GenerateFlags(env TLSEnvironment, secretPath, certPath string) (string, error) {
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
	return ParseFlagTemplate("flags", FlagsTemplate, data), nil
}

// GenerateFlagsEnv to generate flags by environment name
func (environment *Environment) GenerateFlagsEnv(idEnv string, secretPath, certPath string) (string, error) {
	env, err := environment.Get(idEnv)
	if err != nil {
		return "", fmt.Errorf("error getting environment %v", err)
	}
	return environment.GenerateFlags(env, secretPath, certPath)
}
