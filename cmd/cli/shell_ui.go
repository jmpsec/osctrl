package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// shell_ui.go — visual polish for the interactive shell: ANSI colors, a
// braille spinner for in-flight fetches, and emoji accents. Colors and the
// spinner are auto-disabled when stdout is not a TTY (piped output stays
// clean and machine-readable).

// ANSI color codes.
const (
	cReset   = "\x1b[0m"
	cBold    = "\x1b[1m"
	cDim     = "\x1b[2m"
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cBlue    = "\x1b[34m"
	cMagenta = "\x1b[35m"
	cCyan    = "\x1b[36m"
	cGray    = "\x1b[90m"
)

// useColor enables ANSI color output; forceColor lets a user opt in even
// when stdout is piped (e.g. piping into a color-aware pager).
var useColor bool

// spinnerEnabled gates the animated spinner — only on a real terminal so
// piped output never gets spinner frames mixed in.
var spinnerOn bool

func paint(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

// colorCell colorizes well-known status/boolean words for table cells.
func colorCell(s string) string {
	switch s {
	case "active", "ACTIVE", "COMPLETE", "yes":
		return paint(cGreen, s)
	case "inactive", "INACTIVE", "EXPIRED", "DELETED", "no":
		return paint(cRed, s)
	case "—", "-":
		return paint(cGray, s)
	default:
		return s
	}
}

// spinnerEnabled reports whether animated spinners should render.
func spinnerEnabled() bool { return spinnerOn }

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// animate renders a spinner + label until done is closed, then clears the line
// and signals via stopped. Owns the line clear so there's no write race with
// the caller.
func animate(label string, done <-chan struct{}, stopped chan<- struct{}) {
	i := 0
	pad := strings.Repeat(" ", 4)
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	for {
		fmt.Printf("\r%s %s%s", paint(cCyan, spinnerFrames[i]), label, pad)
		i = (i + 1) % len(spinnerFrames)
		select {
		case <-t.C:
		case <-done:
			fmt.Printf("\r\x1b[K")
			close(stopped)
			return
		}
	}
}

// spinGet runs fn with a spinner; returns fn's result. No-op spinner when not
// a TTY.
func spinGet[T any](label string, fn func() (T, error)) (T, error) {
	if !spinnerEnabled() {
		return fn()
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go animate(label, done, stopped)
	res, err := fn()
	close(done)
	<-stopped
	return res, err
}

// spinDo runs a void action with a spinner.
func spinDo(label string, fn func() error) error {
	_, err := spinGet(label, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// isTTY returns true if stdout is an interactive terminal.
func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// initColors sets up color/spinner flags. Called once at shell startup.
func initColors() {
	tty := isTTY()
	useColor = tty || os.Getenv("OSCTRL_CLI_FORCE_COLOR") != ""
	spinnerOn = tty
}

// printBanner prints the welcome banner.
func printBanner(version, mode string) {
	line := paint(cCyan+cBold, "🛡️  osctrl-cli interactive shell")
	fmt.Printf("%s  %s\n", line, paint(cDim, "v"+version))
	fmt.Printf("📡  %s\n", paint(cBlue, mode+" mode"))
	fmt.Printf("💡  %s\n", paint(cGray, "Type 'help' or '?' for help · 'exit' to quit"))
}

// moduleIcon returns an emoji for a module name.
// moduleIcon returns a bare emoji for a module. All chosen glyphs are
// East-Asian-Wide (display width 2) so they align in a fixed-width column.
func moduleIcon(name string) string {
	switch name {
	case "nodes":
		return "🖥️"
	case "queries":
		return "🔍"
	case "carves":
		return "📦"
	case "environments":
		return "🌐"
	case "tags":
		return "🏷️"
	case "users":
		return "👤"
	case "audit":
		return "📜"
	case "settings":
		return "🛠️"
	default:
		return "•"
	}
}
