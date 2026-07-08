package main

import (
	"testing"
)

func TestAnsiStrip(t *testing.T) {
	cases := map[string]string{
		"\x1b[36mhello\x1b[0m":         "hello",
		"\x1b[1m\x1b[31mactive\x1b[0m": "active",
		"plain":                        "plain",
		"\x1b[90m─\x1b[0m":             "─",
	}
	for in, want := range cases {
		if got := ansiStrip(in); got != want {
			t.Fatalf("ansiStrip(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVisibleWidth(t *testing.T) {
	if w := visibleWidth(paint(cGreen, "active")); w != 6 {
		t.Fatalf("visibleWidth colored active = %d want 6", w)
	}
	if w := visibleWidth("inactive"); w != 8 {
		t.Fatalf("visibleWidth inactive = %d want 8", w)
	}
}

func TestPaintNoColor(t *testing.T) {
	prev := useColor
	useColor = false
	defer func() { useColor = prev }()
	if got := paint(cRed, "x"); got != "x" {
		t.Fatalf("paint with color off should be plain, got %q", got)
	}
}

func TestColorCell(t *testing.T) {
	prev := useColor
	useColor = true
	defer func() { useColor = prev }()
	if colorCell("active") != cGreen+"active"+cReset {
		t.Fatal("active should be green")
	}
	if colorCell("inactive") != cRed+"inactive"+cReset {
		t.Fatal("inactive should be red")
	}
	if colorCell("foobar") != "foobar" {
		t.Fatal("unknown cell should be plain")
	}
}

func TestSpinGetNonTty(t *testing.T) {
	// spinnerEnabled() is false in tests (spinnerOn defaults to false), so
	// spinGet should just invoke fn directly.
	v, err := spinGet("test", func() (int, error) { return 7, nil })
	if err != nil || v != 7 {
		t.Fatalf("spinGet returned (%d,%v) want (7,nil)", v, err)
	}
}
