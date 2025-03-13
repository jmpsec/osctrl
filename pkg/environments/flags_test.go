package environments

import (
	"testing"
)

var testEnv = TLSEnvironment{}

func TestGenServerCertsFlag(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		flag := GenServerCertsFlag("")
		if flag != "" {
			t.Errorf("Expected empty flag, got %s", flag)
		}
	})
	t.Run("not empty", func(t *testing.T) {
		flag := GenServerCertsFlag("certificate")
		if flag != "--tls_server_certs=certificate" {
			t.Errorf("Expected flag --tls_server_certs=certificate, got %s", flag)
		}
	})
}

func TestGenCarveBlockSizeFlag(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		flag := GenCarveBlockSizeFlag("")
		if flag != "" {
			t.Errorf("Expected empty flag, got %s", flag)
		}
	})
	t.Run("not empty", func(t *testing.T) {
		flag := GenCarveBlockSizeFlag("blockSize")
		if flag != "--carver_block_size=blockSize" {
			t.Errorf("Expected flag --carver_block_size=blockSize, got %s", flag)
		}
	})
}

func TestGenSingleFlag(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		flag := GenSingleFlag("tmplName", "flagName", "")
		if flag != "--flagName=" {
			t.Errorf("Expected --flagName=, got %s", flag)
		}
	})
	t.Run("not empty", func(t *testing.T) {
		flag := GenSingleFlag("tmplName", "flagName", "flagValue")
		if flag != "--flagName=flagValue" {
			t.Errorf("Expected flag --flagName=flagValue, got %s", flag)
		}
	})
}

func TestParseFlagTemplate(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		flag := ParseFlagTemplate("tmplName", "flagTemplate", nil)
		if flag != "flagTemplate" {
			t.Errorf("Expected empty flag, got %s", flag)
		}
	})
	t.Run("not empty data", func(t *testing.T) {
		flag := ParseFlagTemplate("tmplName", "--{{ .Name }}={{ .Value }}", struct {
			Name  string
			Value string
		}{
			Name:  "flagName",
			Value: "flagValue",
		})
		if flag != "--flagName=flagValue" {
			t.Errorf("Expected flag --flagName=flagValue, got %s", flag)
		}
	})
}
