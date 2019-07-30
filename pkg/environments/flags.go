package environments

import (
	"bytes"
	"text/template"
)

const (
	// FlagsTemplate to generate flags for enrolling nodes
	FlagsTemplate string = `
--host_identifier=uuid
--force=true
--utc=true
--enroll_secret_path={{ .SecretFile }}
--enroll_tls_endpoint=/{{ .Environment.Name }}/{{ .Environment.EnrollPath }}
--config_plugin=tls
--config_tls_endpoint=/{{ .Environment.Name }}/{{ .Environment.ConfigPath }}
--config_tls_refresh={{ .Environment.ConfigInterval }}
--logger_plugin=tls
--logger_tls_compress=true
--logger_tls_endpoint=/{{ .Environment.Name }}/{{ .Environment.LogPath }}
--logger_tls_period={{ .Environment.LogInterval }}
--disable_carver=false
--carver_disable_function=false
--carver_start_endpoint=/{{ .Environment.Name }}/{{ .Environment.CarverInitPath }}
--carver_continue_endpoint=/{{ .Environment.Name }}/{{ .Environment.CarverBlockPath }}
--disable_distributed=false
--distributed_interval={{ .Environment.QueryInterval }}
--distributed_plugin=tls
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/{{ .Environment.Name }}/{{ .Environment.QueryReadPath }}
--distributed_tls_write_endpoint=/{{ .Environment.Name }}/{{ .Environment.QueryWritePath }}
--tls_dump=true
--tls_hostname={{ .Environment.Hostname }}
--tls_server_certs={{ .CertFile }}
`
)

type flagData struct {
	SecretFile  string
	CertFile    string
	Environment TLSEnvironment
}

// GenerateFlags to generate flags
func GenerateFlags(environment TLSEnvironment, secret, cert string) (string, error) {
	t, err := template.New("flags").Parse(FlagsTemplate)
	if err != nil {
		return "", err
	}
	data := flagData{
		SecretFile:  secret,
		CertFile:    cert,
		Environment: environment,
	}
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, data); err != nil {
		return "", err
	}
	return tpl.String(), nil
}
