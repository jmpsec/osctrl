package tags

import (
	"fmt"
	"math/rand"
	"time"
)

// Helper to generate a random color in hex for HTML
func randomColor() string {
	rand.Seed(time.Now().UnixNano())
	red := rand.Intn(255)
	green := rand.Intn(255)
	blue := rand.Intn(255)

	return "#" + getHex(red) + getHex(green) + getHex(blue)
}

// Helper to get the hex from an int
func getHex(num int) string {
	hex := fmt.Sprintf("%x", num)
	if len(hex) == 1 {
		hex = "0" + hex
	}
	return hex
}
