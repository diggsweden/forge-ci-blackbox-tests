// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// inertShebangs are the files whose "#!" literals are data the engine reads
// and never runs. A stand-in for a tool the engine runs is a fake tool
// (faketool_test.go), never a written script.
func inertShebangs() map[string]string {
	return map[string]string{
		"artifact_digest_test.go":    "the script is digested, never run",
		"publish_gradle_test.go":     "a non-executable wrapper the preflight must leave alone",
		"sbom_matrix_test.go":        "the binary's bytes are scanned for an SBOM, never run",
		"subprocess_hygiene_test.go": "the pattern this guard looks for",
	}
}

// inheritedEnvs are the declarations that hand a subprocess the caller's own
// environment. Everything else runs in isolatedEnv or an explicit closed one.
func inheritedEnvs() map[string]string {
	return map[string]string{
		"helpers_test.go:miseBinPaths": "mise finds its installs from the caller's environment; isolatedEnv is built from this answer",
	}
}

// TestSubprocessHygiene_FakesAndEnvironments keeps the rules for the suite's
// own subprocesses in the Go sources of the suite and its scripts tests: no
// shebang outside inertShebangs, no append(os.Environ(), …) outside
// inheritedEnvs, and no syscall.ForkLock, which a test only needs to write
// an executable and run it.
func TestSubprocessHygiene_FakesAndEnvironments(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join(suiteDir, "tests", "blackbox", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	scripts, err := filepath.Glob(filepath.Join(suiteDir, "scripts", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, scripts...)
	if len(files) < 2 {
		t.Fatalf("found %d Go files; this guard would pass whatever the sources contain", len(files))
	}

	usedShebangs, usedEnvs := map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		for _, decl := range file.Decls {
			ast.Inspect(decl, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.BasicLit:
					if value, err := strconv.Unquote(node.Value); err == nil && node.Kind == token.STRING &&
						strings.HasPrefix(value, "#!") {
						usedShebangs[name] = true
						if inertShebangs()[name] == "" {
							t.Errorf("%s: a written script; make the tool a fake in faketool_test.go", fset.Position(node.Pos()))
						}
					}
				case *ast.SelectorExpr:
					if isPackageSelector(node, "syscall", "ForkLock") {
						t.Errorf("%s: syscall.ForkLock; make the tool a fake in faketool_test.go", fset.Position(node.Pos()))
					}
				case *ast.CallExpr:
					if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "append" && len(node.Args) > 0 && isEnvironCall(node.Args[0]) {
						key := name + ":" + declName(decl)
						usedEnvs[key] = true
						if inheritedEnvs()[key] == "" {
							t.Errorf("%s: the caller's environment reaches a subprocess; use isolatedEnv or a closed one", fset.Position(node.Pos()))
						}
					}
				}

				return true
			})
		}
	}
	for name := range inertShebangs() {
		if !usedShebangs[name] {
			t.Errorf("inertShebangs names %s, which has no shebang literal; remove the entry", name)
		}
	}
	for key := range inheritedEnvs() {
		if !usedEnvs[key] {
			t.Errorf("inheritedEnvs names %s, which no longer inherits; remove the entry", key)
		}
	}
}

func isPackageSelector(node *ast.SelectorExpr, pkg, name string) bool {
	ident, ok := node.X.(*ast.Ident)

	return ok && ident.Name == pkg && node.Sel.Name == name
}

func isEnvironCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)

	return ok && isPackageSelector(selector, "os", "Environ")
}

// declName names a top-level function or the first name a var declares.
func declName(decl ast.Decl) string {
	switch decl := decl.(type) {
	case *ast.FuncDecl:
		return decl.Name.Name
	case *ast.GenDecl:
		for _, spec := range decl.Specs {
			if value, ok := spec.(*ast.ValueSpec); ok {
				return value.Names[0].Name
			}
		}
	}

	return ""
}
