package saml

import (
	"strings"
	"testing"
)

func TestConfigValidate_Happy(t *testing.T) {
	cfg := Config{
		IDPMetadataURL:         "https://idp.example.com/metadata",
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_MetadataXMLHappy(t *testing.T) {
	cfg := Config{
		IDPMetadataXML:         "<EntityDescriptor/>",
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_Failures(t *testing.T) {
	base := Config{
		IDPMetadataURL:         "https://idp.example.com/metadata",
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	cases := []struct {
		name string
		mut  func(c *Config)
		want string
	}{
		{
			name: "missing metadata",
			mut: func(c *Config) {
				c.IDPMetadataURL = ""
				c.IDPMetadataXML = ""
			},
			want: "IDPMetadataURL or IDPMetadataXML is required",
		},
		{
			name: "both metadata fields set",
			mut: func(c *Config) {
				c.IDPMetadataXML = "<x/>"
			},
			want: "mutually exclusive",
		},
		{
			name: "no entity id",
			mut: func(c *Config) { c.EntityID = "" },
			want: "EntityID is required",
		},
		{
			name: "no acs url",
			mut: func(c *Config) { c.ACSURL = "" },
			want: "ACSURL is required",
		},
		{
			name: "RequireAssertionSigned must be true (S2)",
			mut:  func(c *Config) { c.RequireAssertionSigned = false },
			want: "RequireAssertionSigned MUST be true",
		},
		{
			name: "RequiredGroups without GroupsAttribute",
			mut: func(c *Config) {
				c.RequiredGroups = []string{"admins"}
				c.GroupsAttribute = ""
			},
			want: "GroupsAttribute",
		},
		{
			name: "username attribute with whitespace",
			mut:  func(c *Config) { c.UsernameAttribute = "uid name" },
			want: "whitespace",
		},
		{
			name: "negative replay window",
			mut:  func(c *Config) { c.ReplayWindow = -1 },
			want: "non-negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestEffectiveReplayWindow(t *testing.T) {
	if got := (Config{}).effectiveReplayWindow(); got != DefaultReplayWindow {
		t.Errorf("default: got %d want %d", got, DefaultReplayWindow)
	}
	if got := (Config{ReplayWindow: 10}).effectiveReplayWindow(); got != 10 {
		t.Errorf("override: got %d want 10", got)
	}
}
