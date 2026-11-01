package environments

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A stored environment certificate must be pinned, never turned into a
// verification bypass; only the explicit insecure flag disables verification.
func TestPrepareOneLinerPinsEnvironmentCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmplCert := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmplCert, tmplCert, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	env := TLSEnvironment{UUID: "u", Hostname: "h", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	raw := sha256.Sum256(der)

	sh, err := QuickAddOneLinerShell(false, env)
	require.NoError(t, err)
	assert.Contains(t, sh, "curl -sk --pinnedpubkey 'sha256//"+base64.StdEncoding.EncodeToString(spki[:])+"' https://h/")

	ps, err := QuickAddOneLinerPowershell(false, env)
	require.NoError(t, err)
	assert.Contains(t, ps, strings.ToUpper(hex.EncodeToString(raw[:])))
	assert.NotContains(t, ps, InsecurePowershellTLS)

	sh, err = QuickAddOneLinerShell(true, env)
	require.NoError(t, err)
	assert.NotContains(t, sh, "pinnedpubkey", "explicit insecure opt-in skips the pin")

	_, err = QuickAddOneLinerShell(false, TLSEnvironment{Certificate: "not a pem"})
	assert.Error(t, err, "an unusable certificate must not fall back to no verification")
}
