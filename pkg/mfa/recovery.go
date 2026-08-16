package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// RecoveryCodeCount is how many single-use codes are handed out when a user
// enrolls (and whenever they regenerate the set). Ten is enough to print or
// stash in a password manager without becoming a liability if the sheet leaks.
const RecoveryCodeCount = 10

// recoveryAlphabet excludes the characters that get misread off a printout:
// 0/O, 1/I/L. 26 symbols, 5 bits of entropy each.
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// recoveryCodeChars is the code length in symbols. 20 symbols over a
// 31-symbol alphabet is ~99 bits — far beyond brute force, which is what
// justifies the fast hash below.
const recoveryCodeChars = 20

// GenerateRecoveryCodes returns fresh plaintext recovery codes, formatted in
// four dash-separated groups for legibility. They are shown to the user once
// and only their hashes are stored.
func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		buf := make([]byte, recoveryCodeChars)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("mfa: reading random recovery code: %w", err)
		}
		var sb strings.Builder
		for i, b := range buf {
			if i > 0 && i%5 == 0 {
				sb.WriteByte('-')
			}
			// Modulo bias here is negligible (256 % 31 skews 8 of 31
			// symbols by ~3%), and irrelevant against a 99-bit code.
			sb.WriteByte(recoveryAlphabet[int(b)%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
	}
	return codes, nil
}

// NormalizeRecoveryCode makes user input comparable: uppercase, no spaces or
// dashes, so "abcde-fghij" and "ABCDEFGHIJ" both work.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

// HashRecoveryCode hashes a code for storage.
//
// SHA-256 rather than bcrypt on purpose: recovery codes are ~99 bits of
// machine-generated randomness, not a user-chosen password, so there is no
// dictionary to slow an attacker down against — and verification has to walk
// every unused code for the user, which at bcrypt cost 12 would put a
// multi-second delay on the login path.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// MatchRecoveryCode compares in constant time.
func MatchRecoveryCode(code, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashRecoveryCode(code)), []byte(hash)) == 1
}
