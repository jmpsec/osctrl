package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// shell_readline.go — a small raw-mode line editor with history and tab
// completion for the interactive shell. No external readline dependency was
// available offline, so this is built on golang.org/x/term (already a CLI dep).
//
// Editing: ←/→/Home/End, Backspace, Delete, Ctrl-A/E/K/U, ↑/↓ history, Tab
// completion, Ctrl-C abort, Ctrl-D EOF on an empty line.

type completer func(line string, cursor int) (candidates []string, commonPrefix string)

type lineEditor struct {
	history  []string
	histIdx  int
	complete completer
	br       *bufio.Reader
}

type interruptErr struct{}

func (interruptErr) Error() string { return "interrupted" }

var errInterrupt = interruptErr{}

// readline reads one edited line. Returns the line (no newline), io.EOF on
// Ctrl-D over an empty line, or errInterrupt on Ctrl-C.
func (le *lineEditor) readline(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return le.readLinePlain(prompt)
	}
	defer func() { _ = term.Restore(fd, old) }()

	out := os.Stdout
	buf := []rune{}
	cursor := 0
	le.histIdx = len(le.history)

	redraw := func() {
		fmt.Fprint(out, "\r"+prompt+string(buf)+"\x1b[K")
		if back := len(buf) - cursor; back > 0 {
			fmt.Fprintf(out, "\x1b[%dD", back)
		}
	}
	redraw()

	insert := func(r rune) {
		buf = append(buf, 0)
		copy(buf[cursor+1:], buf[cursor:])
		buf[cursor] = r
		cursor++
	}
	deleteAt := func(pos int) {
		if pos >= 0 && pos < len(buf) {
			buf = append(buf[:pos], buf[pos+1:]...)
		}
	}

	tmp := make([]byte, 64)
	for {
		n, rerr := os.Stdin.Read(tmp)
		if rerr != nil {
			return "", rerr
		}
		i := 0
		for i < n {
			b := tmp[i]
			switch b {
			case '\r', '\n':
				fmt.Fprintln(out)
				line := string(buf)
				if strings.TrimSpace(line) != "" {
					le.history = append(le.history, line)
				}
				return line, nil
			case 0x03: // Ctrl-C
				fmt.Fprintln(out, "^C")
				return "", errInterrupt
			case 0x04: // Ctrl-D
				if len(buf) == 0 {
					fmt.Fprintln(out)
					return "", io.EOF
				}
				deleteAt(cursor)
				redraw()
			case 0x08, 0x7f: // Backspace
				if cursor > 0 {
					deleteAt(cursor - 1)
					cursor--
					redraw()
				}
			case 0x01: // Ctrl-A
				cursor = 0
				redraw()
			case 0x05: // Ctrl-E
				cursor = len(buf)
				redraw()
			case 0x0b: // Ctrl-K
				buf = buf[:cursor]
				redraw()
			case 0x15: // Ctrl-U
				buf = buf[cursor:]
				cursor = 0
				redraw()
			case 0x09: // Tab
				le.doCompletion(out, &buf, &cursor, redraw)
			case 0x1b:
				seq, consumed := readEscape(tmp[i:], n-i)
				i += consumed
				switch seq {
				case "A": // up — history back
					if le.histIdx > 0 {
						le.histIdx--
						buf = []rune(le.history[le.histIdx])
						cursor = len(buf)
						redraw()
					}
				case "B": // down — history forward
					if le.histIdx < len(le.history)-1 {
						le.histIdx++
						buf = []rune(le.history[le.histIdx])
						cursor = len(buf)
						redraw()
					} else {
						le.histIdx = len(le.history)
						buf = nil
						cursor = 0
						redraw()
					}
				case "C": // right
					if cursor < len(buf) {
						cursor++
						redraw()
					}
				case "D": // left
					if cursor > 0 {
						cursor--
						redraw()
					}
				case "H", "1": // home
					cursor = 0
					redraw()
				case "F", "4": // end
					cursor = len(buf)
					redraw()
				case "3": // delete
					deleteAt(cursor)
					redraw()
				}
				continue
			default:
				r, size := utf8.DecodeRune(tmp[i:n])
				if r == utf8.RuneError && size == 1 {
					i++
					continue
				}
				insert(r)
				redraw()
				i += size
				continue
			}
			i++
		}
	}
}

// doCompletion mutates buf/cursor using the configured completer.
func (le *lineEditor) doCompletion(out *os.File, buf *[]rune, cursor *int, redraw func()) {
	if le.complete == nil {
		return
	}
	cands, common := le.complete(string(*buf), *cursor)
	if len(cands) == 0 {
		return
	}
	start := tokenStart(*buf, *cursor)
	if common != "" && common != string((*buf)[start:*cursor]) {
		newBuf := append([]rune{}, (*buf)[:start]...)
		newBuf = append(newBuf, []rune(common)...)
		newBuf = append(newBuf, (*buf)[*cursor:]...)
		*buf = newBuf
		*cursor = start + len([]rune(common))
		if len(cands) == 1 {
			// add trailing space for a completed word
			*buf = append(*buf, ' ')
			*cursor++
		}
		redraw()
		return
	}
	if len(cands) > 1 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, strings.Join(cands, "  "))
		redraw()
	}
}

// readEscape reads an ANSI escape sequence starting at src[0]==0x1b; returns
// the payload (e.g. "A", "3") and bytes consumed.
func readEscape(src []byte, avail int) (string, int) {
	if avail < 2 {
		return "", 1
	}
	if src[1] != '[' && src[1] != 'O' {
		return "", 2
	}
	if avail < 3 {
		return "", 2
	}
	if avail >= 4 && src[3] == '~' {
		return string(src[2:3]), 4
	}
	return string(src[2:3]), 3
}

// tokenStart is where the whitespace-delimited token under cursor begins.
func tokenStart(buf []rune, cursor int) int {
	for i := cursor; i > 0; i-- {
		if buf[i-1] == ' ' {
			return i
		}
	}
	return 0
}

// readLinePlain is the non-TTY fallback (piped input / scripts). It reads a
// full line so multi-word commands work when stdin is not a terminal.
func (le *lineEditor) readLinePlain(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	if le.br == nil {
		le.br = bufio.NewReader(os.Stdin)
	}
	line, err := le.br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
