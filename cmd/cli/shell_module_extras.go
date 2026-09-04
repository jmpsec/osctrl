package main

import (
	"encoding/json"
	"fmt"
	"github.com/jmpsec/osctrl/pkg/apiclient"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// shell_module_extras.go — console, file explorer, posture, saved-queries
// modules for the interactive shell. Console and file explorer are live
// experiences: they open a session against a node and poll command
// results until the node answers (or the request expires), rendering
// rows as a table the moment they land.

// consoleStatusTimeout is how long a submitted command waits for the node
// to report before we stop polling.
const consoleStatusTimeout = 90 * time.Second

// ─────────────────────────────── console module ───────────────────────────────

func consoleCommands() []shellCmd {
	return []shellCmd{
		{name: "open", args: "<uuid|hostname>", help: "open an interactive console session to a node", min: 1, fn: shConsoleOpen},
	}
}

// shConsoleOpen opens a live console session: submits commands, polls for
// results, and renders them. 'exit' closes the session.
func shConsoleOpen(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	cs, err := storeConsole(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	n, err := spinGet("🖥️  Resolving node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	res, err := spinGet("⌨️  Opening console session", func() (apiclient.ConsoleSessionResponse, error) { return cs.CreateConsoleSession(s.env, n.UUID) })
	if err != nil {
		errf("%v", err)
		return
	}
	session := res.Session
	fmt.Printf("%s session #%d → %s (%s %s)\n",
		paint(cGreen+cBold, "⌨️  console"),
		session.ID, n.Hostname, session.Platform, res.NodeInfo.OsqueryVersion)
	fmt.Printf("%s type SQL, or shell-style commands (ls, cd, pwd, get <path>, tables, help). 'exit' to close.\n",
		paint(cGray, "     "))
	if len(res.History) > 0 {
		fmt.Printf("%s %d history entries restored\n", paint(cGray, "     "), len(res.History))
	}
	sessionID := session.ID
	cwd := session.CWD
	defer func() {
		_ = cs.CloseConsoleSession(s.env, sessionID)
	}()
	for {
		prompt := paint(cCyan+cBold, "osctrl") + " " +
			paint(cMagenta, "("+n.Hostname+":"+cwd+")") + paint(cGreen, "> ")
		line, err := s.rl.readline(prompt)
		if err != nil {
			fmt.Println()
			return
		}
		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" || input == "q" {
			return
		}
		resp, err := cs.SubmitConsoleCommand(s.env, sessionID, input, false)
		if err != nil {
			errf("%v", err)
			continue
		}
		if resp.Parsed.Message != "" {
			fmt.Printf("  %s\n", resp.Parsed.Message)
		}
		if resp.Parsed.Output != "" {
			fmt.Println(indentLines(resp.Parsed.Output, "  "))
		}
		if rows := s.pollConsoleResults(cs, sessionID, resp.Command.ID); rows != nil {
			printResultRows(rows)
		}
		// 'cd' mutates the session cwd server-side — refetch so the
		// prompt tracks where the node really is.
		if resp.Parsed.Kind == console.CommandRemote && resp.Parsed.Command == "cd" {
			if sess, err := cs.GetConsoleSession(s.env, sessionID); err == nil {
				cwd = sess.CWD
			}
		}
	}
}

// pollConsoleResults waits for a command to complete and returns its rows.
// Prints an inline status so the operator sees the node answering.
func (s *shellState) pollConsoleResults(cs consoleStore, sessionID, commandID uint) []map[string]any {
	deadline := time.Now().Add(consoleStatusTimeout)
	for {
		cmd, err := cs.GetConsoleCommand(s.env, sessionID, commandID)
		if err != nil {
			errf("%v", err)
			return nil
		}
		switch cmd.Status {
		case console.StatusCompleted:
			fmt.Printf("\r\x1b[K")
			rows, err := cs.GetConsoleCommandResults(s.env, sessionID, commandID)
			if err != nil {
				errf("%v", err)
				return nil
			}
			return rows
		case console.StatusError:
			fmt.Printf("\r\x1b[K")
			errf("command failed: %s", cmd.Error)
			return nil
		case console.StatusExpired:
			fmt.Printf("\r\x1b[K")
			fmt.Printf("  %s node did not report in time\n", paint(cYellow, "⏱"))
			return nil
		}
		if time.Now().After(deadline) {
			fmt.Printf("\r\x1b[K")
			fmt.Printf("  %s timed out waiting for node\n", paint(cYellow, "⏱"))
			return nil
		}
		fmt.Printf("\r  %s waiting for node…%s",
			paint(cCyan, spinnerFrames[int(time.Now().Unix()%int64(len(spinnerFrames)))]),
			paint(cGray, strings.Repeat(" ", 8)))
		time.Sleep(500 * time.Millisecond)
	}
}

// ─────────────────────────────── file explorer module ───────────────────────────────

func fileExplorerCommands() []shellCmd {
	return []shellCmd{
		{name: "open", args: "<uuid|hostname>", help: "open an interactive file explorer session to a node", min: 1, fn: shFexploreOpen},
	}
}

func shFexploreOpen(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	cs, err := storeConsole(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	n, err := spinGet("🖥️  Resolving node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	res, err := spinGet("🗂️  Opening file explorer session", func() (apiclient.FileExplorerSessionResponse, error) {
		return cs.CreateFileExplorerSession(s.env, n.UUID)
	})
	if err != nil {
		errf("%v", err)
		return
	}
	session := res.Session
	root := session.Root
	if root == "" {
		root = "/"
	}
	fmt.Printf("%s session #%d → %s (%s)\n",
		paint(cGreen+cBold, "🗂️  file explorer"), session.ID, n.Hostname, session.Platform)
	fmt.Printf("%s 'ls <path>', 'stat <path>', 'cd <dir>' (re-roots), 'exit' to close. root: %s\n",
		paint(cGray, "     "), root)
	sessionID := session.ID
	defer func() {
		_ = cs.CloseFileExplorerSession(s.env, sessionID)
	}()
	for {
		prompt := paint(cCyan+cBold, "osctrl") + " " +
			paint(cMagenta, "(fex:"+n.Hostname+")") + paint(cGreen, "> ")
		line, err := s.rl.readline(prompt)
		if err != nil {
			fmt.Println()
			return
		}
		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" || input == "q" {
			return
		}
		tokens := strings.Fields(input)
		cmd, arg := tokens[0], ""
		if len(tokens) > 1 {
			arg = tokens[1]
		}
		switch cmd {
		case "ls", "list", "dir":
			s.fexploreRequest(cs, sessionID, "list", arg)
		case "stat":
			s.fexploreRequest(cs, sessionID, "stat", arg)
		case "cd":
			if arg != "" {
				root = arg
				okf("root: %s", root)
			}
		default:
			errf("unknown file explorer command: %s (ls, stat, cd, exit)", cmd)
		}
	}
}

func (s *shellState) fexploreRequest(cs consoleStore, sessionID uint, action, target string) {
	var req fileexplorer.Request
	var err error
	if action == "stat" {
		req, err = cs.SubmitFileExplorerStat(s.env, sessionID, target)
	} else {
		req, err = cs.SubmitFileExplorerList(s.env, sessionID, target)
	}
	if err != nil {
		errf("%v", err)
		return
	}
	deadline := time.Now().Add(consoleStatusTimeout)
	for {
		req, err = cs.GetFileExplorerRequest(s.env, sessionID, req.ID)
		if err != nil {
			errf("%v", err)
			return
		}
		if req.Status == fileexplorer.StatusCompleted || req.Status == fileexplorer.StatusError || req.Status == fileexplorer.StatusExpired {
			fmt.Printf("\r\x1b[K")
			break
		}
		if time.Now().After(deadline) {
			fmt.Printf("\r\x1b[K")
			fmt.Printf("  %s timed out waiting for node\n", paint(cYellow, "⏱"))
			return
		}
		fmt.Printf("\r  %s waiting for node…%s",
			paint(cCyan, spinnerFrames[int(time.Now().Unix()%int64(len(spinnerFrames)))]),
			paint(cGray, strings.Repeat(" ", 8)))
		time.Sleep(500 * time.Millisecond)
	}
	if req.Status != fileexplorer.StatusCompleted {
		if req.Error != "" {
			errf("%s", req.Error)
		} else {
			errf("request %s", req.Status)
		}
		return
	}
	entries, err := cs.GetFileExplorerResults(s.env, sessionID, req.ID)
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{e.Type, e.Mode, e.Filename, e.Directory, strconv.FormatInt(e.Size, 10)})
	}
	fmt.Printf("%d entries\n", len(entries))
	printTable([]string{"Type", "Mode", "Name", "Directory", "Size"}, rows)
}

// ─────────────────────────────── posture module ───────────────────────────────

func postureCommands() []shellCmd {
	return []shellCmd{
		{name: "show", args: "<uuid|hostname>", help: "show posture data for a node", min: 1, fn: shPostureShow},
		{name: "score", args: "<uuid|hostname>", help: "show SOC2/ISO27001 risk score for a node", min: 1, fn: shPostureScore},
		{name: "profiles", aliases: "ls", args: "", help: "list posture profile templates", fn: shPostureProfiles},
	}
}

func shPostureShow(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ps, err := storePosture(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	n, err := spinGet("🖥️  Resolving node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	records, err := spinGet("🛡️  Fetching posture", func() ([]posture.NodePosture, error) { return ps.NodePosture(s.env, n.UUID) })
	if err != nil {
		errf("%v", err)
		return
	}
	if len(records) == 0 {
		fmt.Printf("no posture data for %s — has a posture profile been assigned?\n", n.Hostname)
		return
	}
	for _, r := range records {
		fmt.Printf("%s (%d rows, last seen %s)\n", paint(cCyan+cBold, r.Category), r.RowCount, shortTime(r.LastSeen))
		var rows []map[string]any
		if err := json.Unmarshal([]byte(r.Summary), &rows); err != nil || len(rows) == 0 {
			fmt.Printf("  %s\n", paint(cGray, "(no rows)"))
			fmt.Println()
			continue
		}
		printResultRows(rows)
		fmt.Println()
	}
}

func shPostureScore(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ps, err := storePosture(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	n, err := spinGet("🖥️  Resolving node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	score, err := spinGet("🛡️  Scoring posture", func() (posture.PostureScore, error) { return ps.NodePostureScore(s.env, n.UUID) })
	if err != nil {
		errf("%v", err)
		return
	}
	color := cGreen
	switch score.RiskLevel {
	case "medium":
		color = cYellow
	case "high", "critical":
		color = cRed
	}
	fmt.Printf("%s %s  %s %s/100  pass %s  warn %s  fail %s\n",
		paint(cCyan+cBold, "🛡️  "+n.Hostname),
		paint(color+cBold, strings.ToUpper(score.RiskLevel)),
		paint(cCyan, "score"), strconv.Itoa(score.TotalScore),
		paint(cGreen, strconv.Itoa(score.PassCount)),
		paint(cYellow, strconv.Itoa(score.WarnCount)),
		paint(cRed, strconv.Itoa(score.FailCount)))
	rows := make([][]string, 0, len(score.Controls))
	for _, c := range score.Controls {
		rows = append(rows, []string{string(c.Framework), c.ControlID, c.Title, c.Status, string(c.Severity), c.Detail})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		order := map[string]int{"fail": 0, "warn": 1, "pass": 2}
		return order[rows[i][3]] < order[rows[j][3]]
	})
	printTable([]string{"Framework", "Control", "Title", "Status", "Severity", "Detail"}, rows)
}

func shPostureProfiles(s *shellState, _ []string) {
	ps, err := storePosture(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	profiles, err := spinGet("🛡️  Fetching profiles", func() ([]posture.PostureProfile, error) { return ps.PostureProfiles() })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(profiles))
	for _, p := range profiles {
		rows = append(rows, []string{p.ID, p.Name, p.Platform, p.Description, strconv.Itoa(len(p.Queries))})
	}
	printTable([]string{"ID", "Name", "Platform", "Description", "Checks"}, rows)
}

// ─────────────────────────────── saved queries module ───────────────────────────────

func savedCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "", help: "list saved queries in the active env", fn: shSavedList},
		{name: "show", args: "<name>", help: "show a saved query", min: 1, fn: shSavedShow},
		{name: "save", args: "<name> <sql>", help: "save a new query", min: 2, fn: shSavedSave},
		{name: "update", args: "<name> <sql>", help: "update a saved query body", min: 2, fn: shSavedUpdate},
		{name: "delete", aliases: "rm", args: "<name>", help: "delete a saved query", min: 1, fn: shSavedDelete},
		{name: "run", args: "<name>", help: "dispatch a saved query (uses set options)", min: 1, fn: shSavedRun},
		{name: "samples", args: "", help: "browse the built-in query template library", fn: shSavedSamples},
	}
}

func shSavedList(s *shellState, _ []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	items, err := spinGet("💾 Fetching saved queries", func() ([]types.SavedQueryView, error) { return ss.SavedQueries(s.env) })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(items))
	for _, q := range items {
		rows = append(rows, []string{q.Name, q.Creator, q.Query, shortTime(q.UpdatedAt)})
	}
	fmt.Printf("%d saved queries in %s\n", len(items), s.env)
	printTable([]string{"Name", "Creator", "Query", "Updated"}, rows)
}

func shSavedShow(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	items, err := spinGet("💾 Fetching saved queries", func() ([]types.SavedQueryView, error) { return ss.SavedQueries(s.env) })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, q := range items {
		if q.Name == args[0] {
			fmt.Printf("Name:    %s\n", q.Name)
			fmt.Printf("Creator: %s\n", q.Creator)
			fmt.Printf("Created: %s\n", shortTime(q.CreatedAt))
			fmt.Printf("Updated: %s\n", shortTime(q.UpdatedAt))
			fmt.Printf("Query:\n%s\n", q.Query)
			return
		}
	}
	errf("saved query not found: %s", args[0])
}

func shSavedSave(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	sql := strings.Join(args[1:], " ")
	if err := ss.SaveQuery(s.env, args[0], sql); err != nil {
		errf("%v", err)
		return
	}
	okf("saved query %s in %s", args[0], s.env)
}

func shSavedUpdate(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	sql := strings.Join(args[1:], " ")
	if err := ss.UpdateSavedQuery(s.env, args[0], sql); err != nil {
		errf("%v", err)
		return
	}
	okf("updated saved query %s", args[0])
}

func shSavedDelete(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	if !s.confirm(fmt.Sprintf("Delete saved query %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	if err := ss.DeleteSavedQuery(s.env, args[0]); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted saved query %s", args[0])
}

func shSavedRun(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	items, err := spinGet("💾 Fetching saved queries", func() ([]types.SavedQueryView, error) { return ss.SavedQueries(s.env) })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, q := range items {
		if q.Name == args[0] {
			req := s.buildRunReq(q.Query)
			if err := spinDo("🔍 Dispatching query", func() error { return s.store.RunQuery(req) }); err != nil {
				errf("%v", err)
				return
			}
			okf("dispatched saved query %s", args[0])
			return
		}
	}
	errf("saved query not found: %s", args[0])
}

func shSavedSamples(s *shellState, _ []string) {
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	samples, err := spinGet("💾 Fetching samples", func() ([]queries.QuerySample, error) { return ss.QuerySamples() })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(samples))
	for _, smp := range samples {
		rows = append(rows, []string{smp.Name, string(smp.Category), strings.Join(platformsOf(smp), ","), smp.Description})
	}
	fmt.Printf("%d sample templates\n", len(samples))
	printTable([]string{"Name", "Category", "Platforms", "Description"}, rows)
}

func platformsOf(s queries.QuerySample) []string {
	out := make([]string, 0, len(s.Platforms))
	for _, p := range s.Platforms {
		out = append(out, string(p))
	}
	return out
}

// ─────────────────────────────── node logs (nodes module extension) ───────────────────────────────

func shNodeLogs(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	ss, err := storeSaved(s.store)
	if err != nil {
		errf("%v", err)
		return
	}
	logType := "result"
	if len(args) > 1 {
		logType = args[1]
	}
	if logType != "result" && logType != "status" {
		errf("log type must be 'result' or 'status'")
		return
	}
	n, err := spinGet("🖥️  Resolving node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	body, err := spinGet("📜 Fetching logs", func() (string, error) { return ss.NodeLogs(s.env, logType, n.UUID) })
	if err != nil {
		errf("%v", err)
		return
	}
	fmt.Println(body)
}

// ─────────────────────────────── row rendering helpers ───────────────────────────────

// columnKeys returns the sorted keys of a result-row map for table headers.
func columnKeys(row map[string]any) []string {
	keys := make([]string, 0, len(row))
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// printResultRows renders arbitrary query-result rows as a table.
func printResultRows(rows []map[string]any) {
	if len(rows) == 0 {
		fmt.Printf("  %s\n", paint(cGray, "(no rows)"))
		return
	}
	headers := columnKeys(rows[0])
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		cells := make([]string, 0, len(headers))
		for _, h := range headers {
			v, ok := r[h]
			if !ok {
				cells = append(cells, "")
				continue
			}
			cells = append(cells, fmt.Sprintf("%v", v))
		}
		table = append(table, cells)
	}
	printTable(headers, table)
}

// indentLines prefixes every line with pad.
func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n")
}
