package main

import (
	"fmt"
	"strconv"
	"strings"
)

// label prints a right-aligned colored field label for detail views.
func label(k string) string {
	return paint(cCyan, fmt.Sprintf("%-15s", k+":"))
}

// shell_modules.go — per-module command sets and handlers.

// ─────────────────────────────── nodes ───────────────────────────────

func nodesCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "[active|inactive|all]", help: "list nodes in the active env (default: all)", fn: shNodesList},
		{name: "search", args: "<query>", help: "search nodes by hostname/uuid/ip/user", min: 1, fn: shNodesSearch},
		{name: "show", args: "<uuid|hostname>", help: "show node detail", min: 1, fn: shNodesShow},
		{name: "delete", aliases: "rm", args: "<uuid>", help: "delete (archive) a node", min: 1, fn: shNodesDelete},
		{name: "tag", args: "<uuid> <tag>", help: "apply a tag to a node", min: 2, fn: shNodesTag},
	}
}

func shNodesList(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	target := "all"
	if len(args) > 0 {
		target = args[0]
	}
	nds, err := spinGet("🖥️  Fetching nodes", func() ([]nodeRow, error) { return s.store.Nodes(s.env, target) })
	if err != nil {
		errf("%v", err)
		return
	}
	s.cacheNodeKeys(nds)
	rows := make([][]string, 0, len(nds))
	for _, n := range nds {
		st := "active"
		if !n.Active {
			st = "inactive"
		}
		rows = append(rows, []string{n.Hostname, n.UUID, n.Platform, n.PlatformVersion, n.OsqueryVersion, n.IPAddress, n.LastSeen, st})
	}
	fmt.Printf("%d %s nodes in %s\n", len(nds), target, s.env)
	printTable([]string{"Hostname", "UUID", "Platform", "Version", "Osquery", "IP", "LastSeen", "Status"}, rows)
}

func shNodesSearch(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	nds, err := spinGet("🖥️  Fetching nodes", func() ([]nodeRow, error) { return s.store.Nodes(s.env, "all") })
	if err != nil {
		errf("%v", err)
		return
	}
	s.cacheNodeKeys(nds)
	q := strings.ToLower(strings.Join(args, " "))
	rows := make([][]string, 0)
	for _, n := range nds {
		hay := strings.ToLower(n.Hostname + " " + n.UUID + " " + n.IPAddress + " " + n.Localname + " " + n.Username)
		if strings.Contains(hay, q) {
			st := "active"
			if !n.Active {
				st = "inactive"
			}
			rows = append(rows, []string{n.Hostname, n.UUID, n.Platform, n.IPAddress, n.LastSeen, st})
		}
	}
	fmt.Printf("%d matches for %q\n", len(rows), q)
	printTable([]string{"Hostname", "UUID", "Platform", "IP", "LastSeen", "Status"}, rows)
}

func shNodesShow(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	n, err := spinGet("🖥️  Fetching node", func() (nodeRow, error) { return s.store.Node(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	status := "active"
	if !n.Active {
		status = "inactive"
	}
	fmt.Printf("%s %s\n", label("Hostname"), n.Hostname)
	fmt.Printf("%s %s\n", label("Localname"), n.Localname)
	fmt.Printf("%s %s\n", label("UUID"), n.UUID)
	fmt.Printf("%s %s\n", label("Environment"), n.Environment)
	fmt.Printf("%s %s %s\n", label("Platform"), n.Platform, n.PlatformVersion)
	fmt.Printf("%s %s\n", label("Osquery"), n.OsqueryVersion)
	fmt.Printf("%s %s\n", label("IP address"), n.IPAddress)
	fmt.Printf("%s %s\n", label("Username"), n.Username)
	fmt.Printf("%s %s / %s\n", label("CPU / Memory"), n.CPU, n.Memory)
	fmt.Printf("%s %s\n", label("Hardware serial"), n.HardwareSerial)
	fmt.Printf("%s %d\n", label("Bytes received"), n.BytesReceived)
	fmt.Printf("%s %s\n", label("Last seen"), n.LastSeen)
	fmt.Printf("%s %s\n", label("First seen"), n.FirstSeen)
	fmt.Printf("%s %s\n", label("Status"), colorCell(status))
}

func shNodesDelete(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	uuid := args[0]
	if !s.confirm(fmt.Sprintf("Delete node %s?", uuid)) {
		fmt.Println("aborted")
		return
	}
	if err := spinDo("🗑️  Deleting node", func() error { return s.store.DeleteNode(s.env, uuid) }); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted node %s", uuid)
}

func shNodesTag(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	if err := spinDo("🏷️  Tagging node", func() error { return s.store.TagNode(s.env, args[0], args[1]) }); err != nil {
		errf("%v", err)
		return
	}
	okf("tagged node %s with %s", args[0], args[1])
}

func (s *shellState) cacheNodeKeys(nds []nodeRow) {
	s.nodeKeys = s.nodeKeys[:0]
	for _, n := range nds {
		s.nodeKeys = append(s.nodeKeys, n.UUID, n.Hostname)
	}
}

// ─────────────────────────────── queries ───────────────────────────────

func queriesCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "[active|completed|expired|deleted|hidden|all]", help: "list on-demand queries", fn: shQueriesList},
		{name: "show", args: "<name>", help: "show query detail", min: 1, fn: shQueriesShow},
		{name: "run", args: "<sql>", help: "run a new query (uses set options)", min: 1, fn: shQueriesRun},
		{name: "results", args: "<name>", help: "show query results", min: 1, fn: shQueriesResults},
		{name: "complete", args: "<name>", help: "mark query complete", min: 1, fn: shQueriesComplete},
		{name: "expire", args: "<name>", help: "expire query", min: 1, fn: shQueriesExpire},
		{name: "delete", aliases: "rm", args: "<name>", help: "delete query", min: 1, fn: shQueriesDelete},
		{name: "options", args: "", help: "show current run options", fn: shShowOptions},
	}
}

func shQueriesList(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	target := "active"
	if len(args) > 0 {
		target = args[0]
	}
	qs, err := spinGet("🔍 Fetching queries", func() ([]queryRow, error) { return s.store.Queries(s.env, target) })
	if err != nil {
		errf("%v", err)
		return
	}
	s.cacheQueryNames(qs)
	rows := make([][]string, 0, len(qs))
	for _, q := range qs {
		rows = append(rows, []string{q.Name, q.Creator, q.Status, strconv.Itoa(q.Expected), strconv.Itoa(q.Executions), strconv.Itoa(q.Errors), q.Query})
	}
	fmt.Printf("%d %s queries in %s\n", len(qs), target, s.env)
	printTable([]string{"Name", "Creator", "Status", "Expected", "Exec", "Err", "Query"}, rows)
}

func shQueriesShow(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	qs, err := spinGet("🔍 Fetching queries", func() ([]queryRow, error) { return s.store.Queries(s.env, "all") })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, q := range qs {
		if q.Name == args[0] {
			printQueryDetail(q)
			return
		}
	}
	errf("query not found: %s", args[0])
}

func printQueryDetail(q queryRow) {
	fmt.Printf("Name:        %s\n", q.Name)
	fmt.Printf("Creator:     %s\n", q.Creator)
	fmt.Printf("Type:        %s\n", q.Type)
	fmt.Printf("Status:      %s\n", q.Status)
	fmt.Printf("Hidden:      %s\n", boolTag(q.Hidden))
	fmt.Printf("Expected:    %d\n", q.Expected)
	fmt.Printf("Executions:  %d\n", q.Executions)
	fmt.Printf("Errors:      %d\n", q.Errors)
	fmt.Printf("Target:      %s\n", q.Target)
	fmt.Printf("Created:     %s\n", q.Created)
	fmt.Printf("Expiration:  %s\n", q.Expiration)
	fmt.Printf("Query:\n%s\n", q.Query)
}

func shQueriesRun(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	req := s.buildRunReq(strings.Join(args, " "))
	if err := spinDo("🔍 Dispatching query", func() error { return s.store.RunQuery(req) }); err != nil {
		errf("%v", err)
		return
	}
	okf("query dispatched in %s", s.env)
}

func shQueriesResults(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	body, err := spinGet("🔍 Loading results", func() (string, error) { return s.store.QueryResults(s.env, args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	fmt.Println(body)
}

func shQueriesComplete(s *shellState, args []string) { lifecycleQuery(s, args[0], "complete") }
func shQueriesExpire(s *shellState, args []string)   { lifecycleQuery(s, args[0], "expire") }
func shQueriesDelete(s *shellState, args []string) {
	if !s.confirm(fmt.Sprintf("Delete query %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	lifecycleQuery(s, args[0], "delete")
}

func lifecycleQuery(s *shellState, name, action string) {
	if !s.requireEnv() {
		return
	}
	err := spinDo("🔍 "+action, func() error {
		switch action {
		case "complete":
			return s.store.CompleteQuery(s.env, name)
		case "expire":
			return s.store.ExpireQuery(s.env, name)
		case "delete":
			return s.store.DeleteQuery(s.env, name)
		}
		return nil
	})
	if err != nil {
		errf("%v", err)
		return
	}
	okf("%s %s", action, name)
}

func (s *shellState) cacheQueryNames(qs []queryRow) {
	s.queryNames = s.queryNames[:0]
	for _, q := range qs {
		s.queryNames = append(s.queryNames, q.Name)
	}
}

// ─────────────────────────────── carves ───────────────────────────────

func carvesCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "[active|completed|expired|deleted|all]", help: "list carve queries", fn: shCarvesList},
		{name: "files", args: "", help: "list carved files in the active env", fn: shCarvesFiles},
		{name: "show", args: "<name>", help: "show carve query detail", min: 1, fn: shCarvesShow},
		{name: "run", args: "<path>", help: "start a carve (uses set options)", min: 1, fn: shCarvesRun},
		{name: "complete", args: "<name>", help: "mark carve complete", min: 1, fn: shCarvesComplete},
		{name: "expire", args: "<name>", help: "expire carve", min: 1, fn: shCarvesExpire},
		{name: "delete", aliases: "rm", args: "<name>", help: "delete carve", min: 1, fn: shCarvesDelete},
		{name: "options", args: "", help: "show current run options", fn: shShowOptions},
	}
}

func shCarvesList(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	target := "active"
	if len(args) > 0 {
		target = args[0]
	}
	qs, err := spinGet("📦 Fetching carves", func() ([]queryRow, error) { return s.store.CarveQueries(s.env, target) })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(qs))
	for _, q := range qs {
		rows = append(rows, []string{q.Name, q.Creator, q.Status, strconv.Itoa(q.Expected), strconv.Itoa(q.Executions), q.Query})
	}
	fmt.Printf("%d %s carve queries in %s\n", len(qs), target, s.env)
	printTable([]string{"Name", "Creator", "Status", "Expected", "Exec", "Query"}, rows)
}

func shCarvesFiles(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	cs, err := spinGet("📦 Fetching carved files", func() ([]carveRow, error) { return s.store.Carves(s.env) })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, []string{c.CarveID, c.QueryName, c.UUID, c.Path, c.Status, fmt.Sprintf("%d/%d", c.CompletedBlocks, c.TotalBlocks), c.CompletedAt})
	}
	fmt.Printf("%d carved files in %s\n", len(cs), s.env)
	printTable([]string{"CarveID", "Query", "UUID", "Path", "Status", "Blocks", "Completed"}, rows)
}

func shCarvesShow(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	qs, err := spinGet("📦 Fetching carves", func() ([]queryRow, error) { return s.store.CarveQueries(s.env, "all") })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, q := range qs {
		if q.Name == args[0] {
			printQueryDetail(q)
			return
		}
	}
	errf("carve query not found: %s", args[0])
}

func shCarvesRun(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	req := s.buildRunReq(args[0])
	if err := spinDo("📦 Dispatching carve", func() error { return s.store.RunCarve(req) }); err != nil {
		errf("%v", err)
		return
	}
	okf("carve dispatched in %s", s.env)
}

func shCarvesComplete(s *shellState, args []string) { lifecycleCarve(s, args[0], "complete") }
func shCarvesExpire(s *shellState, args []string)   { lifecycleCarve(s, args[0], "expire") }
func shCarvesDelete(s *shellState, args []string) {
	if !s.confirm(fmt.Sprintf("Delete carve %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	lifecycleCarve(s, args[0], "delete")
}

func lifecycleCarve(s *shellState, name, action string) {
	if !s.requireEnv() {
		return
	}
	err := spinDo("📦 "+action, func() error {
		switch action {
		case "complete":
			return s.store.CompleteCarve(s.env, name)
		case "expire":
			return s.store.ExpireCarve(s.env, name)
		case "delete":
			return s.store.DeleteCarve(s.env, name)
		}
		return nil
	})
	if err != nil {
		errf("%v", err)
		return
	}
	okf("%s carve %s", action, name)
}

// buildRunReq assembles a runQueryReq from active env + set options.
func (s *shellState) buildRunReq(query string) runQueryReq {
	exp, _ := strconv.Atoi(s.opts["expiration"])
	return runQueryReq{
		Env:       s.env,
		Query:     query,
		UUIDs:     csvSplit(s.opts["uuids"]),
		Hosts:     csvSplit(s.opts["hosts"]),
		Platforms: csvSplit(s.opts["platforms"]),
		Tags:      csvSplit(s.opts["tags"]),
		Hidden:    parseHidden(s.opts["hidden"]),
		ExpHours:  exp,
	}
}

func shShowOptions(s *shellState, _ []string) {
	fmt.Printf("env:        %s\n", s.env)
	fmt.Printf("uuids:      %s\n", s.opts["uuids"])
	fmt.Printf("hosts:      %s\n", s.opts["hosts"])
	fmt.Printf("platforms:  %s\n", s.opts["platforms"])
	fmt.Printf("tags:       %s\n", s.opts["tags"])
	fmt.Printf("hidden:     %s\n", s.opts["hidden"])
	fmt.Printf("expiration: %s (hours)\n", s.opts["expiration"])
}

// ─────────────────────────────── environments ───────────────────────────────

func envCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "", help: "list environments", fn: shEnvList},
		{name: "show", args: "<name>", help: "show environment detail", min: 1, fn: shEnvShow},
		{name: "delete", aliases: "rm", args: "<name>", help: "delete an environment (db)", min: 1, fn: shEnvDelete},
		{name: "extend-enroll", args: "<name>", help: "extend enroll URL expiry", min: 1, fn: shEnvAction("enroll", "extend")},
		{name: "rotate-enroll", args: "<name>", help: "rotate enroll URL", min: 1, fn: shEnvAction("enroll", "rotate")},
		{name: "expire-enroll", args: "<name>", help: "expire enroll URL", min: 1, fn: shEnvAction("enroll", "expire")},
		{name: "notexpire-enroll", args: "<name>", help: "mark enroll URL non-expiring", min: 1, fn: shEnvAction("enroll", "notexpire")},
		{name: "extend-remove", args: "<name>", help: "extend remove URL expiry", min: 1, fn: shEnvAction("remove", "extend")},
		{name: "rotate-remove", args: "<name>", help: "rotate remove URL", min: 1, fn: shEnvAction("remove", "rotate")},
		{name: "expire-remove", args: "<name>", help: "expire remove URL", min: 1, fn: shEnvAction("remove", "expire")},
		{name: "notexpire-remove", args: "<name>", help: "mark remove URL non-expiring", min: 1, fn: shEnvAction("remove", "notexpire")},
	}
}

func shEnvList(s *shellState, _ []string) { s.showEnvironments() }

func shEnvShow(s *shellState, args []string) {
	es, err := spinGet("🌐 Fetching environments", func() ([]envRow, error) { return s.store.Environments() })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, e := range es {
		if e.Name == args[0] {
			fmt.Printf("Name:          %s\n", e.Name)
			fmt.Printf("UUID:          %s\n", e.UUID)
			fmt.Printf("Hostname:      %s\n", e.Hostname)
			fmt.Printf("Type:          %s\n", e.Type)
			fmt.Printf("Icon:          %s\n", e.Icon)
			fmt.Printf("Debug HTTP:    %s\n", boolTag(e.DebugHTTP))
			fmt.Printf("Accept enrolls:%s\n", boolTag(e.AcceptEnroll))
			fmt.Printf("Enroll expire: %s\n", shortTime(e.EnrollExpire))
			fmt.Printf("Remove expire: %s\n", shortTime(e.RemoveExpire))
			fmt.Printf("Created:       %s\n", shortTime(e.CreatedAt))
			return
		}
	}
	errf("environment not found: %s", args[0])
}

func shEnvDelete(s *shellState, args []string) {
	if s.store.Mode() == "api" {
		errf("environment deletion is not exposed via the REST API; use --db mode")
		return
	}
	if !s.confirm(fmt.Sprintf("Delete environment %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	if err := envs.Delete(args[0]); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted environment %s", args[0])
}

func shEnvAction(target, action string) func(*shellState, []string) {
	return func(s *shellState, args []string) {
		msg, err := s.store.EnvAction(args[0], target, action)
		if err != nil {
			errf("%v", err)
			return
		}
		okf("%s", msg)
	}
}

// ─────────────────────────────── tags ───────────────────────────────

func tagsCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "[env]", help: "list tags (active env if omitted)", fn: shTagsList},
		{name: "show", args: "<name>", help: "show tag (active env)", min: 1, fn: shTagsShow},
		{name: "add", args: "<name> [color=.. icon=.. desc=.. type=.. custom=..]", help: "add a tag", min: 1, fn: shTagsAdd},
		{name: "edit", args: "<name> [color=.. icon=.. desc=.. type=.. custom=..]", help: "edit a tag", min: 1, fn: shTagsEdit},
		{name: "delete", aliases: "rm", args: "<name>", help: "delete a tag", min: 1, fn: shTagsDelete},
	}
}

func shTagsList(s *shellState, args []string) {
	ts, err := spinGet("🏷️  Fetching tags", func() ([]tagRow, error) { return s.store.Tags() })
	if err != nil {
		errf("%v", err)
		return
	}
	env := s.env
	if len(args) > 0 {
		env = args[0]
	}
	rows := make([][]string, 0)
	for _, t := range ts {
		rows = append(rows, []string{t.Name, t.TagType, t.CustomTag, t.Description, t.Color, t.CreatedBy, boolTag(t.AutoTag)})
	}
	fmt.Printf("%d tags\n", len(rows))
	printTable([]string{"Name", "Type", "Custom", "Description", "Color", "Creator", "Auto"}, rows)
	_ = env
}

func shTagsShow(s *shellState, args []string) {
	ts, err := spinGet("🏷️  Fetching tags", func() ([]tagRow, error) { return s.store.Tags() })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, t := range ts {
		if t.Name == args[0] {
			fmt.Printf("Name:        %s\n", t.Name)
			fmt.Printf("Type:        %s\n", t.TagType)
			fmt.Printf("Custom:      %s\n", t.CustomTag)
			fmt.Printf("Description: %s\n", t.Description)
			fmt.Printf("Color:       %s\n", t.Color)
			fmt.Printf("Icon:        %s\n", t.Icon)
			fmt.Printf("Creator:     %s\n", t.CreatedBy)
			fmt.Printf("Auto:        %s\n", boolTag(t.AutoTag))
			return
		}
	}
	errf("tag not found: %s", args[0])
}

func shTagsAdd(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	kv := kvArgs(args[1:])
	if err := s.store.AddTag(s.env, args[0], kv["color"], kv["icon"], kv["desc"], kv["type"], kv["custom"]); err != nil {
		errf("%v", err)
		return
	}
	okf("created tag %s in %s", args[0], s.env)
}

func shTagsEdit(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	kv := kvArgs(args[1:])
	if err := s.store.EditTag(s.env, args[0], kv["color"], kv["icon"], kv["desc"], kv["type"], kv["custom"]); err != nil {
		errf("%v", err)
		return
	}
	okf("edited tag %s", args[0])
}

func shTagsDelete(s *shellState, args []string) {
	if !s.requireEnv() {
		return
	}
	if !s.confirm(fmt.Sprintf("Delete tag %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	if err := s.store.DeleteTag(s.env, args[0]); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted tag %s", args[0])
}

// ─────────────────────────────── users ───────────────────────────────

func usersCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "", help: "list users", fn: shUsersList},
		{name: "show", args: "<username>", help: "show user detail", min: 1, fn: shUsersShow},
		{name: "add", args: "<username> password=<..> [email=.. fullname=.. admin=true service=false]", help: "add a user", min: 1, fn: shUsersAdd},
		{name: "edit", args: "<username> <password|email|fullname|admin|service>=<value>", help: "edit a user field", min: 2, fn: shUsersEdit},
		{name: "delete", aliases: "rm", args: "<username>", help: "delete a user", min: 1, fn: shUsersDelete},
		{name: "permissions", aliases: "perms", args: "<username>", help: "show a user's permissions", min: 1, fn: shUsersPerms},
	}
}

func shUsersList(s *shellState, _ []string) {
	us, err := spinGet("👤 Fetching users", func() ([]userRow, error) { return s.store.Users() })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(us))
	for _, u := range us {
		rows = append(rows, []string{u.Username, u.Fullname, u.Email, boolTag(u.Admin), boolTag(u.Service), u.LastAccess})
	}
	fmt.Printf("%d users\n", len(us))
	printTable([]string{"Username", "Fullname", "Email", "Admin", "Service", "LastAccess"}, rows)
}

func shUsersShow(s *shellState, args []string) {
	us, err := spinGet("👤 Fetching users", func() ([]userRow, error) { return s.store.Users() })
	if err != nil {
		errf("%v", err)
		return
	}
	for _, u := range us {
		if u.Username == args[0] {
			fmt.Printf("Username:   %s\n", u.Username)
			fmt.Printf("Fullname:   %s\n", u.Fullname)
			fmt.Printf("Email:      %s\n", u.Email)
			fmt.Printf("Admin:      %s\n", boolTag(u.Admin))
			fmt.Printf("Service:    %s\n", boolTag(u.Service))
			fmt.Printf("Last access:%s\n", u.LastAccess)
			return
		}
	}
	errf("user not found: %s", args[0])
}

func shUsersAdd(s *shellState, args []string) {
	kv := kvArgs(args[1:])
	admin := parseBool(kv["admin"])
	service := parseBool(kv["service"])
	if err := s.store.CreateUser(args[0], kv["password"], kv["email"], kv["fullname"], admin, service); err != nil {
		errf("%v", err)
		return
	}
	okf("created user %s", args[0])
}

func shUsersEdit(s *shellState, args []string) {
	field := args[1]
	if idx := strings.Index(field, "="); idx > 0 {
		key := field[:idx]
		val := field[idx+1:]
		if err := s.store.EditUserField(args[0], key, val); err != nil {
			errf("%v", err)
			return
		}
		okf("updated %s.%s", args[0], key)
		return
	}
	errf("usage: edit <username> <field>=<value>")
}

func shUsersDelete(s *shellState, args []string) {
	if !s.confirm(fmt.Sprintf("Delete user %s?", args[0])) {
		fmt.Println("aborted")
		return
	}
	if err := s.store.DeleteUser(args[0]); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted user %s", args[0])
}

func shUsersPerms(s *shellState, args []string) {
	ps, err := spinGet("👤 Fetching permissions", func() ([]permRow, error) { return s.store.Permissions(args[0]) })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(ps))
	for _, p := range ps {
		rows = append(rows, []string{p.Username, p.Environment, p.AccessType, boolTag(p.AccessValue), p.GrantedBy})
	}
	printTable([]string{"Username", "Environment", "Access", "Granted", "GrantedBy"}, rows)
}

// ─────────────────────────────── audit ───────────────────────────────

func auditCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "", help: "list audit logs", fn: shAuditList},
	}
}

func shAuditList(s *shellState, _ []string) {
	ls, err := spinGet("📜 Fetching audit logs", func() ([]auditRow, error) { return s.store.AuditLogs() })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(ls))
	for _, a := range ls {
		rows = append(rows, []string{a.When, a.Username, a.LogType, a.Service, a.SourceIP, a.Line})
	}
	fmt.Printf("%d audit entries\n", len(ls))
	printTable([]string{"When", "User", "Type", "Service", "IP", "Entry"}, rows)
}

// ─────────────────────────────── settings ───────────────────────────────

func settingsCommands() []shellCmd {
	return []shellCmd{
		{name: "list", aliases: "ls", args: "", help: "list configuration values", fn: shSettingsList},
		{name: "add", args: "<service> <name> <type> <value>", help: "add a setting (db)", min: 4, fn: shSettingsAdd},
		{name: "update", args: "<service> <name> <type> <value>", help: "update a setting (db)", min: 4, fn: shSettingsUpdate},
		{name: "delete", aliases: "rm", args: "<service> <name>", help: "delete a setting (db)", min: 2, fn: shSettingsDelete},
	}
}

func shSettingsList(s *shellState, _ []string) {
	vs, err := spinGet("⚙️  Fetching settings", func() ([]settingRow, error) { return s.store.Settings() })
	if err != nil {
		errf("%v", err)
		return
	}
	rows := make([][]string, 0, len(vs))
	for _, v := range vs {
		rows = append(rows, []string{v.Service, v.Name, v.Type, v.Value, v.Info})
	}
	fmt.Printf("%d settings\n", len(vs))
	printTable([]string{"Service", "Name", "Type", "Value", "Info"}, rows)
}

func shSettingsAdd(s *shellState, args []string) {
	if err := s.store.AddSetting(args[0], args[1], args[2], args[3]); err != nil {
		errf("%v", err)
		return
	}
	okf("added setting %s/%s", args[0], args[1])
}

func shSettingsUpdate(s *shellState, args []string) {
	if err := s.store.UpdateSetting(args[0], args[1], args[2], args[3]); err != nil {
		errf("%v", err)
		return
	}
	okf("updated setting %s/%s", args[0], args[1])
}

func shSettingsDelete(s *shellState, args []string) {
	if !s.confirm(fmt.Sprintf("Delete setting %s/%s?", args[0], args[1])) {
		fmt.Println("aborted")
		return
	}
	if err := s.store.DeleteSetting(args[0], args[1]); err != nil {
		errf("%v", err)
		return
	}
	okf("deleted setting %s/%s", args[0], args[1])
}
