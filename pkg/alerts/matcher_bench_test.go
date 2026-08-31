package alerts

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
)

// benchmarkSnapshot builds a worst-case-ish rule snapshot: N rules
// mixing substring and regex, field-scoped and any-field.
func benchmarkSnapshot(n int) *RuleSet {
	rs := &RuleSet{}
	for i := 0; i < n; i++ {
		matchType := MatchTypeSubstring
		pattern := fmt.Sprintf("needle-%d", i)
		if i%3 == 0 {
			matchType = MatchTypeRegex
			pattern = fmt.Sprintf(`^needle-%d-[a-z]+$`, i)
		}
		field := ""
		if i%2 == 0 {
			field = "path"
		}
		cr, err := CompileRule(AlertRule{
			Model:      ruleWithID(uint(i + 1)),
			Name:       fmt.Sprintf("rule-%d", i),
			Source:     SourceResultLog,
			MatchType:  matchType,
			MatchField: field,
			MatchValue: pattern,
			ChannelIDs: "[1]",
		})
		if err != nil {
			panic(err)
		}
		rs.result = append(rs.result, cr)
	}
	return rs
}

func benchmarkBatch(rows int) []types.LogResultData {
	cols := map[string]string{
		"path":     "/usr/local/bin/binary",
		"action":   "modified",
		"md5":      "d41d8cd98f00b204e9800998ecf8427e",
		"sha256":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"hostname": "node-07.example.com",
		"username": "operator",
		"process":  "/usr/sbin/sshd -D",
	}
	raw, _ := json.Marshal(cols)
	logs := make([]types.LogResultData, rows)
	for i := range logs {
		logs[i] = types.LogResultData{
			HostIdentifier: fmt.Sprintf("UUID-%04d", i),
			Name:           "file_events",
			Columns:        raw,
		}
	}
	return logs
}

// BenchmarkMatchResultLogs20x500 is the Stage-1 validation gate: 20
// rules over a 500-row batch must complete well under 5ms on CI-class
// hardware. The regex path is deliberately included so the benchmark
// exercises the more expensive matcher.
func BenchmarkMatchResultLogs20x500(b *testing.B) {
	rs := benchmarkSnapshot(20)
	logs := benchmarkBatch(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rs.MatchResultLogs(logs)
	}
}

func BenchmarkMatchResultLogs50x1000(b *testing.B) {
	rs := benchmarkSnapshot(50)
	logs := benchmarkBatch(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rs.MatchResultLogs(logs)
	}
}

func BenchmarkMatchResultLogsEmptyRules(b *testing.B) {
	rs := &RuleSet{}
	logs := benchmarkBatch(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rs.MatchResultLogs(logs)
	}
}
