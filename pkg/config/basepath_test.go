package config

import "testing"

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"/", "", false},
		{"osctrl", "/osctrl", false},
		{"/osctrl/", "/osctrl", false},
		{" /a/b-c_d.e ", "/a/b-c_d.e", false},
		{"/a//b", "", true},
		{"/a/../b", "", true},
		{"/a/./b", "", true},
		{"/os ctrl", "", true},
		{"/osctrl;Domain=evil.com", "", true},
		{"/osctrl\r\nSet-Cookie: x=y", "", true},
		{"/os%2fctrl", "", true},
		{"/ö", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeBasePath(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeBasePath(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}
