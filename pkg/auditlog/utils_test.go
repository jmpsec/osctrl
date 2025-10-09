package auditlog

import "testing"

func TestLogTypeToString(t *testing.T) {
	tests := []struct {
		input    uint
		expected string
	}{
		{1, "Login"},
		{2, "Logout"},
		{3, "Node"},
		{4, "Query"},
		{5, "Carve"},
		{6, "Tag"},
		{7, "Environment"},
		{8, "Setting"},
		{9, "Visit"},
		{10, "User"},
		{0, "Unknown"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		result := LogTypeToString(tt.input)
		if result != tt.expected {
			t.Errorf("LogTypeToString(%d) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSeverityToString(t *testing.T) {
	tests := []struct {
		input    uint
		expected string
	}{
		{1, "Info"},
		{2, "Warning"},
		{3, "Error"},
		{0, "Unknown"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		result := SeverityToString(tt.input)
		if result != tt.expected {
			t.Errorf("SeverityToString(%d) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}
