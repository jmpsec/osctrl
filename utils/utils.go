package utils

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const bytesUnit = 1024

// BytesReceivedConversion - Helper to format bytes received into KB, MB, TB... Binary format
func BytesReceivedConversion(b int) string {
	if b < bytesUnit {
		return fmt.Sprintf("%d bytes", b)
	}
	div, exp := int64(bytesUnit), 0
	for n := b / bytesUnit; n >= bytesUnit; n /= bytesUnit {
		div *= bytesUnit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

// Helper to generate a random MD5 to be used with queries/carves
func RandomForNames() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	hasher := md5.New()
	_, _ = hasher.Write([]byte(fmt.Sprintf("%x", b)))
	return hex.EncodeToString(hasher.Sum(nil))
}
