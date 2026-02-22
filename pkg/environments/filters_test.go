package environments

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIconFilter tests the IconFilter function
func TestIconFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{"valid lowercase", "myicon", true},
		{"valid with numbers", "icon123", true},
		{"valid with dash", "my-icon", true},
		{"valid with underscore", "my_icon", true},
		{"valid complex", "my_icon-123", true},
		{"valid single char", "a", true},
		{"valid number only", "123", true},
		{"valid dashes only", "---", true},
		{"valid underscores only", "___", true},

		// Invalid inputs
		{"invalid uppercase", "MyIcon", false},
		{"invalid space", "my icon", false},
		{"invalid special char", "my@icon", false},
		{"invalid dot", "my.icon", false},
		{"invalid slash", "my/icon", false},
		{"invalid backslash", "my\\icon", false},
		{"invalid parentheses", "my(icon)", false},
		{"invalid brackets", "my[icon]", false},
		{"invalid braces", "my{icon}", false},
		{"invalid exclamation", "my!icon", false},
		{"invalid question", "my?icon", false},
		{"invalid asterisk", "my*icon", false},
		{"invalid plus", "my+icon", false},
		{"invalid equals", "my=icon", false},
		{"invalid percent", "my%icon", false},
		{"invalid ampersand", "my&icon", false},
		{"invalid hash", "my#icon", false},
		{"invalid dollar", "my$icon", false},
		{"invalid caret", "my^icon", false},
		{"invalid tilde", "my~icon", false},
		{"invalid pipe", "my|icon", false},
		{"invalid comma", "my,icon", false},
		{"invalid semicolon", "my;icon", false},
		{"invalid colon", "my:icon", false},
		{"invalid quote", "my'icon", false},
		{"invalid double quote", "my\"icon", false},
		{"invalid backtick", "my`icon", false},
		{"invalid less than", "my<icon", false},
		{"invalid greater than", "my>icon", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IconFilter(tt.input)
			assert.Equal(t, tt.expected, result, "IconFilter(%q) = %v, expected %v", tt.input, result, tt.expected)
		})
	}
}

// TestEnvTypeFilter tests the EnvTypeFilter function
func TestEnvTypeFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{"valid osquery", "osquery", true},

		// Invalid inputs
		{"invalid uppercase", "OSQUERY", false},
		{"invalid mixed case", "OsQuery", false},
		{"invalid empty", "", false},
		{"invalid other", "other", false},
		{"invalid elasticsearch", "elasticsearch", false},
		{"invalid splunk", "splunk", false},
		{"invalid random", "random", false},
		{"invalid with space", "os query", false},
		{"invalid with dash", "os-query", false},
		{"invalid with underscore", "os_query", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnvTypeFilter(tt.input)
			assert.Equal(t, tt.expected, result, "EnvTypeFilter(%q) = %v, expected %v", tt.input, result, tt.expected)
		})
	}
}

// TestHostnameFilter tests the HostnameFilter function
func TestHostnameFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{"valid simple", "hostname", true},
		{"valid with numbers", "host123", true},
		{"valid with dash", "my-host", true},
		{"valid with dot", "my.host", true},
		{"valid FQDN", "server.example.com", true},
		{"valid with uppercase", "MyHost", true},
		{"valid mixed case FQDN", "Server.Example.Com", true},
		{"valid subdomain", "sub.domain.example.com", true},
		{"valid complex", "MyHost-123.example.com", true},
		{"valid IP-like", "192.168.1.1", true},
		{"valid single char", "a", true},
		{"valid uppercase", "HOSTNAME", true},
		{"valid start with number", "1host", true},
		{"valid multiple dashes", "my-host-name", true},
		{"valid multiple dots", "my.host.name.com", true},

		// Invalid inputs
		{"invalid underscore", "my_host", false},
		{"invalid space", "my host", false},
		{"invalid special char", "my@host", false},
		{"invalid slash", "my/host", false},
		{"invalid backslash", "my\\host", false},
		{"invalid parentheses", "my(host)", false},
		{"invalid brackets", "my[host]", false},
		{"invalid braces", "my{host}", false},
		{"invalid exclamation", "my!host", false},
		{"invalid question", "my?host", false},
		{"invalid asterisk", "my*host", false},
		{"invalid plus", "my+host", false},
		{"invalid equals", "my=host", false},
		{"invalid percent", "my%host", false},
		{"invalid ampersand", "my&host", false},
		{"invalid hash", "my#host", false},
		{"invalid dollar", "my$host", false},
		{"invalid caret", "my^host", false},
		{"invalid tilde", "my~host", false},
		{"invalid pipe", "my|host", false},
		{"invalid comma", "my,host", false},
		{"invalid semicolon", "my;host", false},
		{"invalid colon", "my:host", false},
		{"invalid quote", "my'host", false},
		{"invalid double quote", "my\"host", false},
		{"invalid backtick", "my`host", false},
		{"invalid less than", "my<host", false},
		{"invalid greater than", "my>host", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HostnameFilter(tt.input)
			assert.Equal(t, tt.expected, result, "HostnameFilter(%q) = %v, expected %v", tt.input, result, tt.expected)
		})
	}
}

// TestEnvNameFilter tests the EnvNameFilter function
func TestEnvNameFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{"valid lowercase", "myenv", true},
		{"valid uppercase", "MYENV", true},
		{"valid mixed case", "MyEnv", true},
		{"valid with numbers", "env123", true},
		{"valid with dash", "my-env", true},
		{"valid with underscore", "my_env", true},
		{"valid complex lowercase", "my_env-123", true},
		{"valid complex mixed", "My_Env-123", true},
		{"valid complex uppercase", "MY_ENV-123", true},
		{"valid single char lowercase", "a", true},
		{"valid single char uppercase", "A", true},
		{"valid number only", "123", true},
		{"valid dashes only", "---", true},
		{"valid underscores only", "___", true},
		{"valid start with uppercase", "Production", true},
		{"valid start with number", "1env", true},
		{"valid CamelCase", "ProductionEnv", true},
		{"valid snake_case", "production_env", true},
		{"valid kebab-case", "production-env", true},
		{"valid SCREAMING_SNAKE_CASE", "PRODUCTION_ENV", true},
		{"valid all caps with dash", "PROD-ENV", true},

		// Invalid inputs
		{"invalid space", "my env", false},
		{"invalid dot", "my.env", false},
		{"invalid special char", "my@env", false},
		{"invalid slash", "my/env", false},
		{"invalid backslash", "my\\env", false},
		{"invalid parentheses", "my(env)", false},
		{"invalid brackets", "my[env]", false},
		{"invalid braces", "my{env}", false},
		{"invalid exclamation", "my!env", false},
		{"invalid question", "my?env", false},
		{"invalid asterisk", "my*env", false},
		{"invalid plus", "my+env", false},
		{"invalid equals", "my=env", false},
		{"invalid percent", "my%env", false},
		{"invalid ampersand", "my&env", false},
		{"invalid hash", "my#env", false},
		{"invalid dollar", "my$env", false},
		{"invalid caret", "my^env", false},
		{"invalid tilde", "my~env", false},
		{"invalid pipe", "my|env", false},
		{"invalid comma", "my,env", false},
		{"invalid semicolon", "my;env", false},
		{"invalid colon", "my:env", false},
		{"invalid quote", "my'env", false},
		{"invalid double quote", "my\"env", false},
		{"invalid backtick", "my`env", false},
		{"invalid less than", "my<env", false},
		{"invalid greater than", "my>env", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnvNameFilter(tt.input)
			assert.Equal(t, tt.expected, result, "EnvNameFilter(%q) = %v, expected %v", tt.input, result, tt.expected)
		})
	}
}

// TestEnvUUIDFilter tests the EnvUUIDFilter function
func TestEnvUUIDFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid inputs
		{"valid lowercase uuid", "550e8400-e29b-41d4-a716-446655440000", true},
		{"valid short uuid", "abc-123-def", true},
		{"valid with numbers", "123-456-789", true},
		{"valid with dash", "my-uuid", true},
		{"valid lowercase letters", "abcdef", true},
		{"valid numbers only", "123456", true},
		{"valid single char", "a", true},
		{"valid dashes only", "---", true},
		{"valid complex", "a1b2c3-d4e5f6-7890", true},
		{"valid ksuid format", "2abcdefghijklmnopqrstuvwxyz", true},
		{"valid short", "a-b-c", true},

		// Invalid inputs
		{"invalid uppercase", "ABC-123", false},
		{"invalid mixed case", "Abc-123", false},
		{"invalid underscore", "abc_123", false},
		{"invalid space", "abc 123", false},
		{"invalid dot", "abc.123", false},
		{"invalid special char", "abc@123", false},
		{"invalid slash", "abc/123", false},
		{"invalid backslash", "abc\\123", false},
		{"invalid parentheses", "abc(123)", false},
		{"invalid brackets", "abc[123]", false},
		{"invalid braces", "abc{123}", false},
		{"invalid exclamation", "abc!123", false},
		{"invalid question", "abc?123", false},
		{"invalid asterisk", "abc*123", false},
		{"invalid plus", "abc+123", false},
		{"invalid equals", "abc=123", false},
		{"invalid percent", "abc%123", false},
		{"invalid ampersand", "abc&123", false},
		{"invalid hash", "abc#123", false},
		{"invalid dollar", "abc$123", false},
		{"invalid caret", "abc^123", false},
		{"invalid tilde", "abc~123", false},
		{"invalid pipe", "abc|123", false},
		{"invalid comma", "abc,123", false},
		{"invalid semicolon", "abc;123", false},
		{"invalid colon", "abc:123", false},
		{"invalid quote", "abc'123", false},
		{"invalid double quote", "abc\"123", false},
		{"invalid backtick", "abc`123", false},
		{"invalid less than", "abc<123", false},
		{"invalid greater than", "abc>123", false},
		{"invalid uppercase letter", "abcD", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnvUUIDFilter(tt.input)
			assert.Equal(t, tt.expected, result, "EnvUUIDFilter(%q) = %v, expected %v", tt.input, result, tt.expected)
		})
	}
}

// TestVerifyEnvFilters tests the VerifyEnvFilters function
func TestVerifyEnvFilters(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		icon     string
		sType    string
		hostname string
		expected bool
	}{
		// Valid combinations
		{
			name:     "all valid",
			envName:  "Production",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: true,
		},
		{
			name:     "all valid lowercase",
			envName:  "production",
			icon:     "server-icon",
			sType:    "osquery",
			hostname: "localhost",
			expected: true,
		},
		{
			name:     "all valid with underscores and dashes",
			envName:  "prod_env-1",
			icon:     "my_icon-01",
			sType:    "osquery",
			hostname: "host-01.example.com",
			expected: true,
		},
		{
			name:     "all valid uppercase name",
			envName:  "PRODUCTION",
			icon:     "icon",
			sType:    "osquery",
			hostname: "HOST",
			expected: true,
		},
		{
			name:     "all valid with numbers",
			envName:  "env123",
			icon:     "icon456",
			sType:    "osquery",
			hostname: "192.168.1.1",
			expected: true,
		},

		// Invalid combinations - name
		{
			name:     "invalid name with space",
			envName:  "prod env",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "invalid name with dot",
			envName:  "prod.env",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "invalid name with special char",
			envName:  "prod@env",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "empty name",
			envName:  "",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},

		// Invalid combinations - icon
		{
			name:     "invalid icon with uppercase",
			envName:  "production",
			icon:     "Server",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "invalid icon with space",
			envName:  "production",
			icon:     "my icon",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "invalid icon with dot",
			envName:  "production",
			icon:     "my.icon",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "empty icon",
			envName:  "production",
			icon:     "",
			sType:    "osquery",
			hostname: "prod.example.com",
			expected: false,
		},

		// Invalid combinations - sType
		{
			name:     "invalid type",
			envName:  "production",
			icon:     "server",
			sType:    "invalid",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "invalid type uppercase",
			envName:  "production",
			icon:     "server",
			sType:    "OSQUERY",
			hostname: "prod.example.com",
			expected: false,
		},
		{
			name:     "empty type",
			envName:  "production",
			icon:     "server",
			sType:    "",
			hostname: "prod.example.com",
			expected: false,
		},

		// Invalid combinations - hostname
		{
			name:     "invalid hostname with underscore",
			envName:  "production",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod_host",
			expected: false,
		},
		{
			name:     "invalid hostname with space",
			envName:  "production",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod host",
			expected: false,
		},
		{
			name:     "invalid hostname with special char",
			envName:  "production",
			icon:     "server",
			sType:    "osquery",
			hostname: "prod@host",
			expected: false,
		},
		{
			name:     "empty hostname",
			envName:  "production",
			icon:     "server",
			sType:    "osquery",
			hostname: "",
			expected: false,
		},

		// Multiple invalid fields
		{
			name:     "multiple invalid fields",
			envName:  "prod env",
			icon:     "Server",
			sType:    "invalid",
			hostname: "prod_host",
			expected: false,
		},
		{
			name:     "all empty",
			envName:  "",
			icon:     "",
			sType:    "",
			hostname: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyEnvFilters(tt.envName, tt.icon, tt.sType, tt.hostname)
			assert.Equal(t, tt.expected, result, "VerifyEnvFilters(%q, %q, %q, %q) = %v, expected %v",
				tt.envName, tt.icon, tt.sType, tt.hostname, result, tt.expected)
		})
	}
}
