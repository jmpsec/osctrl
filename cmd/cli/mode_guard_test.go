package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// dbManagerGlobals are the package-level managers only initialised with --db.
var dbManagerGlobals = []string{"adminUsers", "envs", "nodesmgr", "tagsmgr", "queriesmgr", "filecarves", "settingsmgr", "auditlogsmgr", "db"}

// mentions reports whether n contains an identifier with one of the names.
func mentions(n ast.Node, names ...string) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok {
			for _, name := range names {
				found = found || id.Name == name
			}
		}
		return !found
	})
	return found
}

// TestCommandsRegisteredForTheirMode keeps actions from being reachable in a
// mode whose globals (DB managers or osctrlAPI) are nil, which is a panic.
//
// Limits: it only matches identifier names inside the registered function's own
// body; use through a helper function is not detected, and only registrations
// of a plain function identifier (cliWrapper*(name)) are inspected.
func TestCommandsRegisteredForTheirMode(t *testing.T) {
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	funcs := map[string]*ast.FuncDecl{}
	var mainFile *ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if name == "main.go" {
			mainFile = f
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	// (i) and (ii): the plain cliWrapper means the action handles both modes.
	ast.Inspect(mainFile, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		wrapper, ok := call.Fun.(*ast.Ident)
		arg, isIdent := call.Args[0].(*ast.Ident)
		if !ok || !isIdent || funcs[arg.Name] == nil || !strings.HasPrefix(wrapper.Name, "cliWrapper") {
			return true
		}
		fd := funcs[arg.Name]
		usesAPI := mentions(fd.Body, "osctrlAPI", "apiFlag")
		usesDB := mentions(fd.Body, append([]string{"dbFlag"}, dbManagerGlobals...)...)
		switch {
		case wrapper.Name == "cliWrapper" && !usesAPI:
			t.Errorf("%s only uses the database: register it with cliWrapperDB", arg.Name)
		case wrapper.Name == "cliWrapper" && !usesDB:
			t.Errorf("%s only uses the API: register it with cliWrapperAPI", arg.Name)
		case wrapper.Name == "cliWrapperDB" && mentions(fd.Body, "osctrlAPI"):
			t.Errorf("%s is registered DB-only but uses osctrlAPI", arg.Name)
		case wrapper.Name == "cliWrapperAPI" && usesDB:
			t.Errorf("%s is registered API-only but uses dbFlag or a DB manager", arg.Name)
		}
		return true
	})
	// (iii): a bare `if apiFlag {` runs with --db too (apiFlag defaults to
	// true) unless it is an else-if branch.
	for name, fd := range funcs {
		if name == "cliWrapperMode" || name == "checkAPI" { // checkAPI builds its own client
			continue
		}
		elseIfs := map[*ast.IfStmt]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if s, ok := n.(*ast.IfStmt); ok {
				if e, ok := s.Else.(*ast.IfStmt); ok {
					elseIfs[e] = true
				}
				if id, ok := s.Cond.(*ast.Ident); ok && id.Name == "apiFlag" && !elseIfs[s] {
					t.Errorf("%s: bare `if apiFlag {` at %s: use `else if apiFlag`", name, fset.Position(s.Pos()))
				}
			}
			return true
		})
	}
}
