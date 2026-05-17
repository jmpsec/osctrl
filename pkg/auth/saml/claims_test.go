package saml

import (
	"strings"
	"testing"

	crewjam "github.com/crewjam/saml"
)

func TestPickSAMLUsername_PrefersConfiguredAttribute(t *testing.T) {
	attrs := map[string][]string{
		"uid":   {"alice"},
		"email": {"alice@example.com"},
	}
	got := pickSAMLUsername("nameid-fallback", attrs, "uid")
	if got != "alice" {
		t.Fatalf("got %q want alice", got)
	}
}

func TestPickSAMLUsername_FallsBackToNameID(t *testing.T) {
	got := pickSAMLUsername("alice@example.com", nil, "uid")
	if got != "alice@example.com" {
		t.Fatalf("got %q want alice@example.com", got)
	}
}

func TestPickSAMLUsername_AttrPresentButEmpty(t *testing.T) {
	// IdP emits the attribute but with an empty value — fall through
	// to NameID rather than producing an empty username.
	attrs := map[string][]string{
		"uid": {""},
	}
	got := pickSAMLUsername("alice-nameid", attrs, "uid")
	if got != "alice-nameid" {
		t.Fatalf("got %q want alice-nameid", got)
	}
}

func TestPickSAMLUsername_NoConfigured(t *testing.T) {
	attrs := map[string][]string{"anything": {"unused"}}
	got := pickSAMLUsername("alice-nameid", attrs, "")
	if got != "alice-nameid" {
		t.Fatalf("got %q want alice-nameid", got)
	}
}

func TestSanitizeUsername_AcceptRejectMatrix(t *testing.T) {
	good := []string{
		"alice",
		"alice123",
		"alice-tester",
		"alice_tester",
		"A",
		"123",
		strings.Repeat("a", 64),
	}
	for _, u := range good {
		if got := sanitizeUsername(u); got != u {
			t.Errorf("%q should pass, got %q", u, got)
		}
	}
	bad := []string{
		"",
		strings.Repeat("a", 65),
		"alice@example.com",
		"alice b",
		"alice;DROP TABLE users",
		"alice\nadmin",          // audit-log poisoning
		"alice\x00root",         // NUL splicing
		"alice<script>alert(1)", // XSS path
		"alice/bob",
		"alice..\\..\\root",
	}
	for _, u := range bad {
		if got := sanitizeUsername(u); got != "" {
			t.Errorf("%q should be rejected, got %q", u, got)
		}
	}
}

func TestSanitizeUsername_TrimWhitespace(t *testing.T) {
	if got := sanitizeUsername("  alice  "); got != "alice" {
		t.Fatalf("trim: got %q want alice", got)
	}
}

func TestCollectAttributes_NameAndFriendlyName(t *testing.T) {
	assertion := &crewjam.Assertion{
		AttributeStatements: []crewjam.AttributeStatement{
			{
				Attributes: []crewjam.Attribute{
					{
						Name:         "urn:oid:0.9.2342.19200300.100.1.1",
						FriendlyName: "uid",
						Values:       []crewjam.AttributeValue{{Value: "alice"}},
					},
					{
						Name:   "groups",
						Values: []crewjam.AttributeValue{{Value: "admins"}, {Value: "ops"}},
					},
				},
			},
		},
	}
	attrs := collectAttributes(assertion)
	if got := attrs["urn:oid:0.9.2342.19200300.100.1.1"]; len(got) != 1 || got[0] != "alice" {
		t.Errorf("expected uid by Name, got %v", got)
	}
	if got := attrs["uid"]; len(got) != 1 || got[0] != "alice" {
		t.Errorf("expected uid by FriendlyName, got %v", got)
	}
	if got := attrs["groups"]; len(got) != 2 || got[0] != "admins" || got[1] != "ops" {
		t.Errorf("expected multi-valued groups, got %v", got)
	}
}

func TestCollectAttributes_EmptyValueIgnored(t *testing.T) {
	assertion := &crewjam.Assertion{
		AttributeStatements: []crewjam.AttributeStatement{
			{
				Attributes: []crewjam.Attribute{
					{
						Name:   "uid",
						Values: []crewjam.AttributeValue{{Value: ""}},
					},
				},
			},
		},
	}
	attrs := collectAttributes(assertion)
	if _, present := attrs["uid"]; present {
		t.Errorf("empty value should not produce a uid entry, got %v", attrs)
	}
}

func TestCollectAttributes_NilAssertion(t *testing.T) {
	if got := collectAttributes(nil); len(got) != 0 {
		t.Errorf("nil assertion should produce empty map, got %v", got)
	}
}

func TestHasSAMLRequiredGroup(t *testing.T) {
	attrs := map[string][]string{
		"groups": {"users", "admins"},
	}
	if !hasSAMLRequiredGroup(attrs, "groups", []string{"admins"}) {
		t.Error("admins should match")
	}
	if hasSAMLRequiredGroup(attrs, "groups", []string{"super-secret-admins"}) {
		t.Error("super-secret-admins should not match")
	}
	// Disabled gate (empty required) returns true.
	if !hasSAMLRequiredGroup(attrs, "groups", nil) {
		t.Error("empty required list should be a no-op (true)")
	}
	// Missing attribute denies.
	if hasSAMLRequiredGroup(map[string][]string{}, "groups", []string{"admins"}) {
		t.Error("missing groups attribute should deny")
	}
}

func TestDecodeSAMLGroups(t *testing.T) {
	attrs := map[string][]string{
		"groups": {"users", "", "admins"},
	}
	got := decodeSAMLGroups(attrs, "groups")
	if len(got) != 2 || got[0] != "users" || got[1] != "admins" {
		t.Errorf("expected [users admins], got %v", got)
	}
	// Empty attribute name → nil
	if got := decodeSAMLGroups(attrs, ""); got != nil {
		t.Errorf("empty groupsAttr should yield nil, got %v", got)
	}
	// Attribute absent → nil
	if got := decodeSAMLGroups(attrs, "missing"); got != nil {
		t.Errorf("missing attr should yield nil, got %v", got)
	}
}

func TestFirstAttribute(t *testing.T) {
	attrs := map[string][]string{
		"email": {"alice@example.com"},
		"mail":  {"alice@fallback.com"},
	}
	if got := firstAttribute(attrs, "email", "mail"); got != "alice@example.com" {
		t.Errorf("email preferred, got %q", got)
	}
	if got := firstAttribute(attrs, "missing", "mail"); got != "alice@fallback.com" {
		t.Errorf("mail fallback, got %q", got)
	}
	if got := firstAttribute(attrs, "missing1", "missing2"); got != "" {
		t.Errorf("all-missing should return empty, got %q", got)
	}
}
