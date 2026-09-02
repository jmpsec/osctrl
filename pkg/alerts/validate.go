package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// errors.go + channel decode helpers.

var (
	// ErrRuleNotFound is returned by manager Get/Update/Delete.
	ErrRuleNotFound = errors.New("alert rule not found")
	// ErrChannelNotFound is returned by channel manager methods.
	ErrChannelNotFound = errors.New("alert channel not found")
	// ErrRuleExists is returned on duplicate (name, environment).
	ErrRuleExists = errors.New("alert rule already exists")
	// ErrChannelExists is returned on duplicate (name, environment).
	ErrChannelExists = errors.New("alert channel already exists")
	// ErrInvalidSource is returned when Source is not a known source.
	ErrInvalidSource = errors.New("invalid alert source")
	// ErrInvalidRule wraps every ValidateRule failure.
	ErrInvalidRule = errors.New("invalid alert rule")
	// errInvalidMatchType guards MatchType.
	errInvalidMatchType = errors.New("invalid match type")
	// errPatternTooLong guards MaxPatternLen.
	errPatternTooLong = errors.New("match pattern exceeds maximum length")
	// ErrTooManyRules guards MaxRulesPerEnv.
	ErrTooManyRules = fmt.Errorf("too many alert rules for one environment (max %d)", MaxRulesPerEnv)
)

// MaxNodeUUIDLen bounds NodeUUID to its column width.
const MaxNodeUUIDLen = 64

// validSources is the closed set of Source values a rule may use.
var validSources = map[string]bool{
	SourceResultLog:     true,
	SourceStatusLog:     true,
	SourceQueryLog:      true,
	SourceNodeInactive:  true,
	SourceNodeRecovered: true,
}

// ValidateRule checks the operator-facing fields of a rule before it is
// stored. Mirrors logsinks.ValidateSink. Every failure wraps
// ErrInvalidRule: these are all operator-input errors, so the API answers
// 400 with the reason instead of an opaque 500.
func ValidateRule(rule AlertRule) error {
	if err := validateRule(rule); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRule, err)
	}
	return nil
}

func validateRule(rule AlertRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("rule name is required")
	}
	if !validSources[rule.Source] {
		return fmt.Errorf("%w: %q", ErrInvalidSource, rule.Source)
	}
	// A node scope, when set, only has to fit the column. It is NOT an
	// RFC-4122 UUID: a node's UUID is osquery's host_identifier
	// uppercased, which is a hostname / instance id / vendor serial
	// under any --host_identifier but "uuid". Parsing it as a UUID
	// rejected legitimate nodes outright.
	if len(strings.TrimSpace(rule.NodeUUID)) > MaxNodeUUIDLen {
		return fmt.Errorf("node_uuid exceeds %d characters", MaxNodeUUIDLen)
	}
	if rule.Source == SourceNodeInactive || rule.Source == SourceNodeRecovered {
		// Node-state rules do no pattern matching.
		return nil
	}
	if strings.TrimSpace(rule.MatchValue) == "" && rule.MatchType != MatchTypeSubstring {
		return errors.New("match value is required")
	}
	if _, err := CompileRule(rule); err != nil {
		return err
	}
	return nil
}

// DecodeChannelIDs parses the JSON channel-ID array. Empty string /
// null decodes to nil.
func DecodeChannelIDs(raw string) ([]uint, error) {
	return decodeChannels(raw)
}

// EncodeChannelIDs serializes channel IDs for storage.
func EncodeChannelIDs(ids []uint) string {
	return encodeChannels(ids)
}

// DecodeChannelIDsOrEmpty parses the channel-ID array and returns an
// empty slice on any error — a convenience for API clients that only
// need display values.
func DecodeChannelIDsOrEmpty(raw string) []uint {
	ids, err := decodeChannels(raw)
	if err != nil || ids == nil {
		return []uint{}
	}
	return ids
}

// decodeChannels parses the JSON channel-ID array. Empty string / null
// decodes to nil.
func decodeChannels(raw string) ([]uint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var ids []uint
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, fmt.Errorf("invalid channel ids: %w", err)
	}
	return ids, nil
}

// encodeChannels serializes channel IDs for storage.
func encodeChannels(ids []uint) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// validateChannels fills cr.channels from the raw JSON on the rule.
func validateChannels(raw string, cr *compiledRule) error {
	ids, err := decodeChannels(raw)
	if err != nil {
		return err
	}
	cr.channels = ids
	return nil
}
