package main

import (
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// Every command must have unique flag names and aliases: urfave/cli aborts the
// whole CLI at startup ("flag defined multiple times") when two collide.
func TestCommandFlagsAreUnique(t *testing.T) {
	var walk func(path string, cmds []*cli.Command)
	walk = func(path string, cmds []*cli.Command) {
		for _, c := range cmds {
			name := strings.TrimSpace(path + " " + c.Name)
			seen := map[string]string{}
			for _, f := range c.Flags {
				for _, n := range f.Names() {
					if prev, ok := seen[n]; ok {
						t.Errorf("%s: %q used by both --%s and --%s", name, n, prev, f.Names()[0])
					}
					seen[n] = f.Names()[0]
				}
			}
			walk(name, c.Commands)
		}
	}
	walk("osctrl-cli", commands)
}
