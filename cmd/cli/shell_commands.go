package main

import (
	"fmt"
	"sort"
	"strings"
)

// shell_commands.go — global commands, module registry, help, completion.

func (s *shellState) buildGlobal() {
	s.global = []shellCmd{
		{name: "help", aliases: "?", args: "", help: "show help for the current context", fn: s.cmdHelp},
		{name: "use", args: "<module>", help: "enter a module context", min: 1, fn: s.cmdUse},
		{name: "back", args: "", help: "leave the current module context", fn: s.cmdBack},
		{name: "set", args: "env <name>  |  <option> <value>", help: "set active env or a run option", fn: s.cmdSet},
		{name: "show", args: "environments | env", help: "list environments", fn: s.cmdShow},
		{name: "stats", args: "", help: "dashboard statistics across environments", fn: s.cmdStats},
		{name: "exit", aliases: "quit", args: "", help: "exit the shell", fn: s.cmdExit},
	}
}

func (s *shellState) buildModules() {
	add := func(m *shellModule) {
		s.modules[m.name] = m
		s.order = append(s.order, m.name)
	}
	add(&shellModule{name: "nodes", label: "nodes", desc: "enrolled osquery nodes", cmds: nodesCommands()})
	add(&shellModule{name: "queries", label: "queries", desc: "on-demand distributed queries", cmds: queriesCommands()})
	add(&shellModule{name: "carves", label: "carves", desc: "file carves", cmds: carvesCommands()})
	add(&shellModule{name: "environments", label: "env", desc: "TLS environments", cmds: envCommands()})
	add(&shellModule{name: "tags", label: "tags", desc: "node tags", cmds: tagsCommands()})
	add(&shellModule{name: "users", label: "users", desc: "users and permissions", cmds: usersCommands()})
	add(&shellModule{name: "audit", label: "audit", desc: "audit logs", cmds: auditCommands()})
	add(&shellModule{name: "settings", label: "settings", desc: "configuration values (db mode)", cmds: settingsCommands()})
}

// ─────────────────────────────── global commands ───────────────────────────────

func (s *shellState) cmdHelp(_ *shellState, _ []string) {
	if s.ctx != "" {
		if m, ok := s.modules[s.ctx]; ok {
			fmt.Printf("%s %s %s\n\n", moduleIcon(m.name), paint(cCyan+cBold, m.name), paint(cGray, "— "+m.desc))
			printCmdHelp(m.cmds)
			fmt.Printf("\n%s\n", paint(cGray, "Global: back, help, set, show, stats, exit"))
			return
		}
	}
	fmt.Printf("%s\n\n", paint(cCyan+cBold, "📚 osctrl-cli interactive shell"))
	fmt.Printf("%s\n", paint(cYellow, "Modules (use <module>):"))
	for _, name := range s.order {
		m := s.modules[name]
		fmt.Printf("  %s  %s  %s\n",
			paint(cMagenta, padRight(moduleIcon(name), 2)),
			paint(cCyan+cBold, padRight(m.name, 13)),
			paint(cGray, m.desc))
	}
	fmt.Println()
	fmt.Printf("%s\n", paint(cYellow, "Global commands:"))
	printCmdHelp(s.global)
}

func printCmdHelp(cmds []shellCmd) {
	for _, c := range cmds {
		usage := c.name
		if c.args != "" {
			usage += " " + c.args
		}
		fmt.Printf("  %s  %s\n", paint(cGreen, padRight(usage, 26)), paint(cGray, c.help))
	}
}

func (s *shellState) cmdUse(_ *shellState, args []string) {
	name := args[0]
	if _, ok := s.modules[name]; !ok {
		errf("no such module: %s", name)
		return
	}
	s.ctx = name
	fmt.Printf("%s %s\n", paint(cCyan, "-> context:"), paint(cMagenta+cBold, name))
}

func (s *shellState) cmdBack(_ *shellState, _ []string) {
	if s.ctx == "" {
		fmt.Println("already at top level")
		return
	}
	fmt.Printf("%s %s\n", paint(cGray, "<- leaving"), paint(cMagenta, s.ctx))
	s.ctx = ""
}

func (s *shellState) cmdExit(_ *shellState, _ []string) { s.running = false }

func (s *shellState) cmdSet(_ *shellState, args []string) {
	if len(args) == 0 {
		fmt.Println("usage: set env <name>   |   set <option> <value>")
		fmt.Println("options: uuids hosts platforms tags hidden expiration")
		return
	}
	if args[0] == "env" {
		if len(args) < 2 {
			fmt.Println("usage: set env <name>")
			return
		}
		s.env = args[1]
		okf("active environment: %s", s.env)
		return
	}
	if len(args) < 2 {
		fmt.Printf("usage: set %s <value>\n", args[0])
		return
	}
	s.opts[args[0]] = args[1]
	okf("%s = %s", args[0], args[1])
}

func (s *shellState) cmdShow(_ *shellState, args []string) {
	if len(args) == 0 || args[0] == "environments" || args[0] == "env" {
		s.showEnvironments()
		return
	}
	errf("unknown show target: %s", args[0])
}

func (s *shellState) showEnvironments() {
	es, err := spinGet("🌐 Fetching environments", func() ([]envRow, error) { return s.store.Environments() })
	if err != nil {
		errf("%v", err)
		return
	}
	s.envNames = nil
	rows := make([][]string, 0, len(es))
	for _, e := range es {
		s.envNames = append(s.envNames, e.Name)
		rows = append(rows, []string{e.Name, e.UUID, e.Hostname, e.Type, boolTag(e.DebugHTTP), boolTag(e.AcceptEnroll)})
	}
	printTable([]string{"Name", "UUID", "Hostname", "Type", "Debug", "Accept"}, rows)
}

func (s *shellState) cmdStats(_ *shellState, _ []string) {
	st, err := spinGet("📊 Loading stats", func() (tuiStats, error) { return s.store.Stats() })
	if err != nil {
		errf("%v", err)
		return
	}
	fmt.Printf("%s %s\n", paint(cCyan, "🖥️  Nodes"), fmt.Sprintf("total %s · active %s · inactive %s (offline after %dh)", paint(cBold, itoa(st.TotalNodes)), paint(cGreen, itoa(st.ActiveNodes)), paint(cRed, itoa(st.InactiveNodes)), st.InactiveHours))
	fmt.Printf("%s queries %s · carves %s\n", paint(cCyan, "🔍 Active"), paint(cBold, itoa(int64(st.TotalActiveQueries))), paint(cBold, itoa(int64(st.TotalActiveCarves))))
	fmt.Printf("%s linux %s · darwin %s · windows %s · other %s\n", paint(cCyan, "💻 Platforms"), itoa(st.Platforms.Linux), itoa(st.Platforms.Darwin), itoa(st.Platforms.Windows), itoa(st.Platforms.Other))
	fmt.Println()
	rows := make([][]string, 0, len(st.Environments))
	for _, e := range st.Environments {
		rows = append(rows, []string{e.Name, itoa(e.Active), itoa(e.Inactive), itoa(e.Total), itoa(int64(e.ActiveQueries)), itoa(int64(e.ActiveCarves))})
	}
	printTable([]string{"Env", "Active", "Inactive", "Total", "Queries", "Carves"}, rows)
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", i)
}

// ─────────────────────────────── completion ───────────────────────────────

func (s *shellState) completer(line string, cursor int) ([]string, string) {
	tokens := strings.Fields(line[:cursor])
	if len(tokens) == 0 {
		// starting a word: offer commands + "use"
		cands := s.commandCandidates()
		return cands, ""
	}
	// completing the first token (a command)
	if len(tokens) == 1 && !strings.HasSuffix(line[:cursor], " ") {
		prefix := tokens[0]
		cands := filterPrefix(s.commandCandidates(), prefix)
		return cands, longestCommonPrefix(cands)
	}
	// completing an argument
	return s.argCandidates(tokens, line, cursor)
}

func (s *shellState) commandCandidates() []string {
	var cands []string
	if s.ctx != "" {
		if m, ok := s.modules[s.ctx]; ok {
			for _, c := range m.cmds {
				cands = append(cands, c.name)
			}
		}
	}
	cands = append(cands, globalNames(s.global)...)
	sort.Strings(cands)
	return dedup(cands)
}

func (s *shellState) argCandidates(tokens []string, line string, cursor int) ([]string, string) {
	cmd := tokens[0]
	switch cmd {
	case "use":
		return dedup(s.order), ""
	case "set":
		if len(tokens) == 1 {
			return []string{"env", "uuids", "hosts", "platforms", "tags", "hidden", "expiration"}, ""
		}
		if tokens[1] == "env" && len(tokens) == 2 {
			return filterPrefix(s.envNames, currentWord(line, cursor)), longestCommonPrefix(s.envNames)
		}
	case "show":
		if len(tokens) == 1 {
			return []string{"environments", "env"}, ""
		}
	}
	// resource-name completion for the active module's primary key
	switch s.ctx {
	case "nodes":
		if cmd == "show" || cmd == "delete" || cmd == "tag" {
			c := filterPrefix(s.nodeKeys, currentWord(line, cursor))
			return c, longestCommonPrefix(c)
		}
	case "queries":
		if cmd == "show" || cmd == "results" || cmd == "complete" || cmd == "expire" || cmd == "delete" {
			c := filterPrefix(s.queryNames, currentWord(line, cursor))
			return c, longestCommonPrefix(c)
		}
	}
	return nil, ""
}

func currentWord(line string, cursor int) string {
	start := cursor
	for start > 0 && line[start-1] != ' ' {
		start--
	}
	return line[start:cursor]
}

func globalNames(cmds []shellCmd) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.name)
		if c.aliases != "" {
			out = append(out, c.aliases)
		}
	}
	return out
}

func filterPrefix(items []string, p string) []string {
	var out []string
	for _, it := range items {
		if strings.HasPrefix(it, p) {
			out = append(out, it)
		}
	}
	return out
}

func longestCommonPrefix(items []string) string {
	if len(items) == 0 {
		return ""
	}
	p := items[0]
	for _, it := range items[1:] {
		for !strings.HasPrefix(it, p) {
			p = p[:len(p)-1]
			if p == "" {
				return ""
			}
		}
	}
	return p
}

func dedup(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}
