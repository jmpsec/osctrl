package utils

import (
	"strconv"
	"time"
)

var (
	// OneMinute - 60 seconds
	OneMinute = 60 * time.Second
	// OneHour - 3600 seconds
	OneHour = 60 * time.Minute
	// SixHours - 21600 seconds
	SixHours = 6 * time.Hour
	// OneDay - 86400 seconds
	OneDay = 24 * time.Hour
	// FifteenDays - 1296000 seconds
	FifteenDays = 15 * OneDay
)

// StringifyTime - Helper to get a string based on the difference of two times
func StringifyTime(seconds int) string {
	var timeStr string
	w := make(map[int]string)
	w[DurationSeconds(OneDay)] = "day"
	w[DurationSeconds(OneHour)] = "hour"
	w[DurationSeconds(OneMinute)] = "minute"
	// Ordering the values will prevent bad values
	ww := [3]int{DurationSeconds(OneDay), DurationSeconds(OneHour), DurationSeconds(OneMinute)}
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

// DurationSeconds - Helper to get the seconds value fom a Duration
func DurationSeconds(duration time.Duration) int {
	return int(duration.Seconds())
}

// TimeTimestamp - Helper to format times in timestamp format
func TimeTimestamp(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// PastFutureTimes - Helper to format past or future times
func PastFutureTimes(t time.Time) string {
	if t.Before(time.Now()) {
		return PastTimeAgo(t)
	}
	return InFutureTime(t)
}

// PastFutureTimesEpoch - Helper to format past or future times
func PastFutureTimesEpoch(ts int64) string {
	return PastFutureTimes(time.Unix(ts, 0))
}

// PastTimeAgo - Helper to format past times only returning one value (minute, hour, day)
func PastTimeAgo(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	now := time.Now()
	seconds := DurationSeconds(now.Sub(t))
	if seconds < 2 {
		return "Just Now"
	}
	if seconds < DurationSeconds(OneMinute) {
		return strconv.Itoa(seconds) + " seconds ago"
	}
	if seconds > DurationSeconds(FifteenDays) {
		return "Since " + t.Format("Mon Jan 02 15:04:05 MST 2006")
	}
	return StringifyTime(seconds) + " ago"
}

// InFutureTime - Helper to format future times only returning one value (minute, hour, day)
func InFutureTime(t time.Time) string {
	if t.IsZero() {
		return "Never Expires"
	}
	now := time.Now()
	seconds := int(t.Sub(now).Seconds())
	if seconds <= 2 {
		return "Expired"
	}
	if seconds < DurationSeconds(OneMinute) {
		return "Expires in " + strconv.Itoa(seconds) + " seconds"
	}
	return "Expires in " + StringifyTime(seconds)
}
