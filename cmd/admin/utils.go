package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// Constants for seconds
const (
	oneMinute = 60
	//fiveMinutes      = 300
	//fifteenMinutes   = 900
	//thirtyMinutes    = 1800
	//fortyfiveMinutes = 2500
	oneHour = 3600
	//threeHours       = 10800
	sixHours = 21600
	//eightHours       = 28800
	//twelveHours      = 43200
	//fifteenHours     = 54000
	//twentyHours      = 72000
	oneDay = 86400
	//twoDays          = 172800
	//sevenDays        = 604800
	fifteenDays = 1296000
)

// Function to generate a secure CSRF token
func generateCSRF() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to check if the CSRF token is valid
func checkCSRFToken(ctxToken, receivedToken string) bool {
	return (strings.TrimSpace(ctxToken) == strings.TrimSpace(receivedToken))
}

// Helper to generate a random MD5 to be used as query name
func generateQueryName() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	hasher := md5.New()
	_, _ = hasher.Write([]byte(fmt.Sprintf("%x", b)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper to generate the carve query
func generateCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + file + "';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + file + "';"
}

func checkValidPlatform(platform string) bool {
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		return false
	}
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}

/*
// Helper to remove backslashes from text
func removeBackslash(rawString string) string {
	return strings.Replace(rawString, "\\", " ", -1)
}

// Helper to generate a link to results for on-demand queries
func resultsSearchLink(name string) string {
		if adminConfig.Logging == settings.LoggingSplunk {
			return strings.Replace(adminConfig.LoggingCfg["search"], "{{NAME}}", removeBackslash(name), 1)
		}
	if adminConfig.Logging == settings.LoggingDB {
		return "/query/logs/" + removeBackslash(name)
	}
	return ""
}
*/

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

// Helper to format past times in timestamp format
func pastTimestamp(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
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

// Helper to format future times only returning one value (minute, hour, day)
func inFutureTime(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	now := time.Now()
	seconds := int(t.Sub(now).Seconds())
	if seconds <= 0 {
		return "Expired"
	}
	return "Expires in " + stringifyTime(seconds)
}

// Helper to calculate the osquery config_hash and skip sending a blob that won't change anything
// https://github.com/facebook/osquery/blob/master/osquery/config/config.cpp#L911
// osquery calculates the SHA1 of the configuration blob, then the SHA1 hash of that
/*
func generateOsqueryConfigHash(config string) string {
	firstHasher := sha1.New()
	secondHasher := sha1.New()
	// Get SHA1 of configuration blob
	_, _ = firstHasher.Write([]byte(config))
	// Get SHA1 of the first hash
	_, _ = secondHasher.Write([]byte(hex.EncodeToString(firstHasher.Sum(nil))))
	return hex.EncodeToString(secondHasher.Sum(nil))
}
*/

// Helper to convert a string into integer
func stringToInteger(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// Helper to convert a string into boolean
func stringToBoolean(s string) bool {
	if s == "yes" || s == "true" || s == "1" {
		return true
	}
	return false
}

// Helper to remove duplicates from []string
func removeStringDuplicates(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	i := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[i] = v
		i++
	}
	return s[:i]
}

// Helper to convert from settings values to JSON configuration
func toJSONConfigurationService(values []settings.SettingValue) types.JSONConfigurationService {
	var cfg types.JSONConfigurationService
	for _, v := range values {
		if v.Name == settings.JSONListener {
			cfg.Listener = v.String
		}
		if v.Name == settings.JSONPort {
			cfg.Port = v.String
		}
		if v.Name == settings.JSONHost {
			cfg.Host = v.String
		}
		if v.Name == settings.JSONAuth {
			cfg.Auth = v.String
		}
		if v.Name == settings.JSONLogging {
			cfg.Logging = v.String
		}
	}
	return cfg
}

// Helper to send metrics if it is enabled
func incMetric(name string) {
	if settingsmgr.ServiceMetrics(settings.ServiceAdmin) {
		_metrics.Inc(name)
	}
}

// Helper to generate the
