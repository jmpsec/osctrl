package environments

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareOneLiner(t *testing.T) {
	envTest := TLSEnvironment{
		Certificate:      "certificate",
		Hostname:         "hostname",
		UUID:             "name",
		RemoveSecretPath: "rPath",
		EnrollSecretPath: "ePath",
	}
	tmpl := "oneliner {{ .InsecureTLS }} 1 {{ .TLSHost }} 2 {{ .Environment }} 3 {{ .SecretPath }}"
	t.Run("empty", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner("", true, TLSEnvironment{}, "")
		assert.Equal(t, oneliner, "")
	})
	t.Run("not empty insecure enroll.sh", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, true, envTest, "enroll.sh")
		assert.Equal(t, oneliner, "oneliner k 1 hostname 2 name 3 ePath")
	})
	t.Run("not empty insecure remove.sh", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, true, envTest, "remove.sh")
		assert.Equal(t, oneliner, "oneliner k 1 hostname 2 name 3 rPath")
	})
	t.Run("not empty insecure enroll.ps1", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, true, envTest, "enroll.ps1")
		assert.Equal(t, oneliner, "oneliner [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; 1 hostname 2 name 3 ePath")
	})
	t.Run("not empty insecure remove.ps1", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, true, envTest, "remove.ps1")
		assert.Equal(t, oneliner, "oneliner [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; 1 hostname 2 name 3 rPath")
	})
	// Empty certificate means secure TLS
	envTest.Certificate = ""
	t.Run("not empty secure enroll.sh", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, false, envTest, "enroll.sh")
		assert.Equal(t, oneliner, "oneliner  1 hostname 2 name 3 ePath")
	})
	t.Run("not empty secure remove.sh", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, false, envTest, "remove.sh")
		assert.Equal(t, oneliner, "oneliner  1 hostname 2 name 3 rPath")
	})
	t.Run("not empty secure enroll.ps1", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, false, envTest, "enroll.ps1")
		assert.Equal(t, oneliner, "oneliner  1 hostname 2 name 3 ePath")
	})
	t.Run("not empty secure remove.ps1", func(t *testing.T) {
		oneliner, _ := PrepareOneLiner(tmpl, false, envTest, "remove.ps1")
		assert.Equal(t, oneliner, "oneliner  1 hostname 2 name 3 rPath")
	})
}
