package main

import (
	"strconv"
	"time"
	"unicode/utf8"
)

// Constants for seconds
const (
	oneMinute   = 60
	oneHour     = 3600
	oneDay      = 86400
	fifteenDays = 1296000
)

// Helper to truncate a string
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n] + "..."
}

// Helper to convert boolean to string
func stringifyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// Helper to get a string based on the difference of two times
func stringifyTime(seconds int) string {
	var timeStr string
	w := make(map[int]string)
	w[oneDay] = "day"
	w[oneHour] = "hour"
	w[oneMinute] = "minute"
	// Ordering the values will prevent bad values
	var ww [3]int
	ww[0] = oneDay
	ww[1] = oneHour
	ww[2] = oneMinute
	for _, v := range ww {
		if seconds >= v {
			d := seconds / v
			dStr := strconv.Itoa(d)
			timeStr = dStr + " " + w[v]
			if d > 1 {
				timeStr += "s"
			}
			break
		}
	}
	return timeStr
}

// Helper to format past times only returning one value (minute, hour, day)
func pastTimeAgo(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	now := time.Now()
	seconds := int(now.Sub(t).Seconds())
	if seconds < 2 {
		return "Just Now"
	}
	if seconds < oneMinute {
		return strconv.Itoa(seconds) + " seconds ago"
	}
	if seconds > fifteenDays {
		return "Since " + t.Format("Mon Jan 02 15:04:05 MST 2006")
	}
	return stringifyTime(seconds) + " ago"
}
