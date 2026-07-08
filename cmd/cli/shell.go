package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
	"gorm.io/gorm/logger"

	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/urfave/cli/v3"
)

// shell.go — Metasploit-style interactive shell for osctrl-cli.
//
// One persistent session holds the backend connection (REST API or local DB)
// open and exposes the same surface as the CLI subcommands through a
// context-based REPL: `use nodes`, `list`, `show <id>`, `run <sql>`, etc. No
// re-invocation of the binary per action.

// shellCmd is one REPL command within a context.
type shellCmd struct {
	name    string
	aliases string // space-separated aliases, matched in dispatch
	args    string // usage hint, e.g. "<uuid|hostname>"
	help    string
	min     int
	fn      func(s *shellState, args []string)
}

// shellModule is a context (nodes, queries, ...) with its own command set.
type shellModule struct {
	name  string
	label string
	desc  string
	cmds  []shellCmd
}

// shellState is the live session.
type shellState struct {
	store   DataStore
	rl      *lineEditor
	env     string // active environment
	ctx     string // current module name ("" = top level)
	modules map[string]*shellModule
	order   []string // module names in display order
	global  []shellCmd
	// run options shared by queries/carves
	opts map[string]string
	// cached resource names for tab completion (refreshed by list/show)
	envNames   []string
	nodeKeys   []string
	queryNames []string
	running    bool
}

// runShell is the action behind the `shell` command.
func runShell(ctx context.Context, cmd *cli.Command) error {
	var store DataStore
	switch {
	case dbFlag:
		store = newDBStore()
	case apiFlag:
		store = newAPIStore(osctrlAPI)
	default:
		return fmt.Errorf("enable --db or --api to use the interactive shell")
	}
	if dbFlag {
		// Silence gorm's logger: it writes carriage returns + SQL traces to
		// stdout that scramble the REPL. The shell surfaces errors via return
		// values, so the trace logger is pure noise here.
		db.Conn.Logger = logger.Discard
		if err := db.Check(); err != nil {
			return fmt.Errorf("db check: %w", err)
		}
	} else {
		if err := osctrlAPI.CheckAPI(); err != nil {
			return fmt.Errorf("api check: %w", err)
		}
	}
	initColors()
	s := newShellState(store)
	printBanner(version.OsctrlVersion, store.Mode())
	// Best-effort: prime env name cache.
	if names, err := store.EnvNames(); err == nil {
		s.envNames = names
		if len(names) > 0 && s.env == "" {
			s.env = names[0]
		}
	}
	return s.loop()
}

func newShellState(store DataStore) *shellState {
	s := &shellState{
		store:   store,
		opts:    map[string]string{"expiration": "6"},
		modules: map[string]*shellModule{},
	}
	s.rl = &lineEditor{complete: s.completer}
	s.buildModules()
	s.buildGlobal()
	return s
}

func (s *shellState) loop() error {
	s.running = true
	for s.running {
		prompt := s.prompt()
		line, err := s.rl.readline(prompt)
		if errors.Is(err, io.EOF) {
			fmt.Println()
			return nil
		}
		if errors.Is(err, errInterrupt) {
			// Ctrl-C: abort current line, stay in shell
			continue
		}
		if err != nil {
			return err
		}
		args := tokenize(line)
		if len(args) == 0 {
			continue
		}
		s.dispatch(args)
	}
	return nil
}

func (s *shellState) prompt() string {
	bracket := paint(cGreen, "> ")
	if s.ctx == "" {
		if s.env != "" {
			return paint(cCyan+cBold, "osctrl") + paint(cYellow, "["+s.env+"]") + bracket
		}
		return paint(cCyan+cBold, "osctrl") + bracket
	}
	ctx := paint(cMagenta, "("+s.ctx+":"+s.env+")")
	if s.env == "" {
		ctx = paint(cMagenta, "("+s.ctx+")")
	}
	return paint(cCyan+cBold, "osctrl") + " " + ctx + bracket
}

// dispatch resolves args[0] to a command in the current module, then global.
func (s *shellState) dispatch(args []string) {
	name := args[0]
	rest := args[1:]
	if s.ctx != "" {
		if m, ok := s.modules[s.ctx]; ok {
			if c, ok := findCmd(m.cmds, name); ok {
				s.runCmd(c, rest)
				return
			}
		}
	}
	if c, ok := findCmd(s.global, name); ok {
		s.runCmd(c, rest)
		return
	}
	fmt.Printf("❌ unknown command: %s — type 'help'\n", name)
}

func (s *shellState) runCmd(c shellCmd, args []string) {
	if c.min > 0 && len(args) < c.min {
		fmt.Printf("usage: %s %s\n", c.name, c.args)
		return
	}
	c.fn(s, args)
}

func findCmd(cmds []shellCmd, name string) (shellCmd, bool) {
	for _, c := range cmds {
		if c.name == name {
			return c, true
		}
		for _, a := range strings.Fields(c.aliases) {
			if a == name {
				return c, true
			}
		}
	}
	return shellCmd{}, false
}

// ─────────────────────────────── helpers ───────────────────────────────

func (s *shellState) confirm(prompt string) bool {
	line, err := s.rl.readline(prompt + " [y/N] ")
	if err != nil {
		return false
	}
	r := strings.ToLower(strings.TrimSpace(line))
	return r == "y" || r == "yes"
}

func (s *shellState) requireEnv() bool {
	if s.env == "" {
		fmt.Println("❌ no active environment. Use: set env <name>  (or: use environments)")
		return false
	}
	return true
}

// printTable renders a header + rows as a clean, borderless ASCII table.
// Plain ASCII (no box-drawing glyphs, no carriage returns) so it never
// scrambles the REPL output regardless of terminal UTF-8 support.
func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("(none)")
		return
	}
	cols := len(headers)
	width := make([]int, cols)
	for i, h := range headers {
		width[i] = visibleWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if w := visibleWidth(r[i]); w > width[i] {
				width[i] = w
			}
		}
	}
	coloredHeaders := make([]string, cols)
	for i, h := range headers {
		coloredHeaders[i] = paint(cCyan+cBold, h)
	}
	printRowRaw(coloredHeaders, width)
	// full-width separator spanning columns + 2-space gutters
	fmt.Println(paint(cGray, strings.Repeat("─", sumWidth(width)+2*(cols-1))))
	for _, r := range rows {
		colored := make([]string, cols)
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			colored[i] = colorCell(cell)
		}
		printRowRaw(colored, width)
	}
}

// padRight pads s with spaces so its visible (display) width equals dw.
func padRight(s string, dw int) string {
	if w := visibleWidth(s); w < dw {
		return s + strings.Repeat(" ", dw-w)
	}
	return s
}

func sumWidth(w []int) int {
	n := 0
	for _, x := range w {
		n += x
	}
	return n
}

// printRowRaw prints one padded row with two-space column gutters. Padding is
// computed from the visible rune width, so ANSI color codes don't misalign.
func printRowRaw(cells []string, width []int) {
	var b strings.Builder
	for i := range width {
		c := ""
		if i < len(cells) {
			c = cells[i]
		}
		b.WriteString(c)
		if i < len(width)-1 {
			b.WriteString(strings.Repeat(" ", width[i]-visibleWidth(c)))
			b.WriteString("  ")
		}
	}
	fmt.Println(b.String())
}

// visibleWidth returns the rune count of s after stripping ANSI escape codes,
// used so colored cells stay aligned.
func visibleWidth(s string) int {
	return runewidth.StringWidth(ansiStrip(s))
}

// ansiStrip removes CSI escape sequences from s.
func ansiStrip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// tokenize splits a command line on whitespace, honoring double-quoted spans.
func tokenize(line string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range line {
		switch {
		case r == '"':
			inQ = !inQ
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// kvArgs parses "key=value" tokens into a map.
func kvArgs(args []string) map[string]string {
	m := map[string]string{}
	for _, a := range args {
		if idx := strings.Index(a, "="); idx > 0 {
			m[a[:idx]] = a[idx+1:]
		}
	}
	return m
}

func okf(format string, a ...any) { fmt.Printf("✅ "+format+"\n", a...) }
func errf(format string, a ...any) {
	fmt.Printf("%s %s\n", paint(cRed, "❌"), fmt.Sprintf(format, a...))
}

// ─────────────────────────────── shared formatters ───────────────────────────────

func boolTag(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func shortTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02 15:04")
}

// parseHidden interprets a "hidden" option value as a boolean.
func parseHidden(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "yes" || v == "y" || v == "true" || v == "1"
}
