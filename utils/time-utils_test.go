package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStringifyTime(t *testing.T) {
	assert := assert.New(t)
	var tests = []struct {
		input    int
		expected string
	}{
		{17, ""},
		{77, "1 minute"},
		{287, "4 minutes"},
		{34117, "9 hours"},
		{456435277, "5282 days"},
	}
	for _, test := range tests {
		assert.Equal(StringifyTime(test.input), test.expected)
	}
}

func TestDurationSeconds(t *testing.T) {
	assert := assert.New(t)
	var tests = []struct {
		input    time.Duration
		expected int
	}{
		{60 * time.Second, 60},
		{60 * time.Minute, 3600},
		{6 * time.Hour, 21600},
		{24 * time.Hour, 86400},
		{15 * OneDay, 1296000},
	}
	for _, test := range tests {
		assert.Equal(DurationSeconds(test.input), test.expected)
	}
}

func TestTimeTimestamp(t *testing.T) {
	assert := assert.New(t)
	var tests = []struct {
		input    time.Time
		expected string
	}{
		{time.Date(1999, time.November, 10, 11, 12, 13, 1234, time.UTC), "942232333"},
		{time.Date(2009, time.December, 11, 12, 13, 14, 12345, time.UTC), "1260533594"},
		{time.Date(2015, time.January, 12, 13, 14, 15, 123456, time.UTC), "1421068455"},
		{time.Date(2019, time.September, 17, 17, 17, 17, 17, time.UTC), "1568740637"},
		{time.Date(2020, time.February, 29, 23, 59, 0, 0, time.UTC), "1583020740"},
	}
	for _, test := range tests {
		assert.Equal(TimeTimestamp(test.input), test.expected)
	}
}

func TestPastFutureTimes(t *testing.T) {
	now := time.Now()
	assert := assert.New(t)
	var tests = []struct {
		input    time.Time
		expected string
	}{
		{now.Add(-1 * time.Second), "Just Now"},
		{now.Add(-57 * time.Second), "57 seconds ago"},
		{now.Add(-10 * time.Minute), "10 minutes ago"},
		{now.Add(-200 * time.Hour), "8 days ago"},
		{time.Date(1999, time.November, 10, 11, 12, 13, 1234, time.UTC), "Since Wed Nov 10 11:12:13 UTC 1999"},
		{now.Add(1 * time.Second), "Expired"},
		{now.Add(37 * time.Second), "Expires in 36 seconds"},
		{now.Add(400 * time.Second), "Expires in 6 minutes"},
		{now.Add(77 * time.Hour), "Expires in 3 days"},
		{time.Time{}, "Never"},
	}
	for _, test := range tests {
		assert.Equal(PastFutureTimes(test.input), test.expected)
	}
}

func TestPastTimeAgo(t *testing.T) {
	now := time.Now()
	assert := assert.New(t)
	var tests = []struct {
		input    time.Time
		expected string
	}{
		{now.Add(-1 * time.Second), "Just Now"},
		{now.Add(-57 * time.Second), "57 seconds ago"},
		{now.Add(-10 * time.Minute), "10 minutes ago"},
		{now.Add(-200 * time.Hour), "8 days ago"},
		{time.Date(1999, time.November, 10, 11, 12, 13, 1234, time.UTC), "Since Wed Nov 10 11:12:13 UTC 1999"},
		{time.Time{}, "Never"},
	}
	for _, test := range tests {
		assert.Equal(PastTimeAgo(test.input), test.expected)
	}
}

func TestInFutureTime(t *testing.T) {
	now := time.Now()
	assert := assert.New(t)
	var tests = []struct {
		input    time.Time
		expected string
	}{
		{now.Add(1 * time.Second), "Expired"},
		{now.Add(57 * time.Second), "Expires in 56 seconds"},
		{now.Add(400 * time.Second), "Expires in 6 minutes"},
		{now.Add(77 * time.Hour), "Expires in 3 days"},
		{time.Time{}, "Never"},
	}
	for _, test := range tests {
		assert.Equal(InFutureTime(test.input), test.expected)
	}
}
