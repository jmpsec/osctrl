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
	_, _ = fmt.Fprintf(hasher, "%x", b)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Intersect returns the intersection of two slices of uints
func Intersect(slice1, slice2 []uint) []uint {
	if len(slice1) == 0 {
		return slice2
	}
	// If slice2 is empty, return slice1
	if len(slice2) == 0 {
		return slice1
	}
	set := make(map[uint]struct{})
	for _, item := range slice1 {
		set[item] = struct{}{} // Add items from slice1 to the set
	}
	intersection := []uint{}
	for _, item := range slice2 {
		if _, exists := set[item]; exists {
			intersection = append(intersection, item)
			delete(set, item) // Ensure uniqueness in the result
		}
	}
	return intersection
}

// Contains checks if string is in the slice
func Contains(all []string, target string) bool {
	for _, s := range all {
		if s == target {
			return true
		}
	}
	return false
}
