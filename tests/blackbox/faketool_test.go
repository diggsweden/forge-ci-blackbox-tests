// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTools are the tools the suite's own test binary stands in for. A fake
// is a link to the test binary named after the tool, so TestMain sees the
// tool's name in argv[0] and runs its behaviour instead of the suite. The
// behaviour gets the directory that holds the link, where it keeps its state:
// the engine may give a tool a closed environment, but not another directory.
func fakeTools() map[string]func(dir string, args []string) int {
	return map[string]func(string, []string) int{
		"buildah":    fakeBuildah,
		"cosign":     fakeCosign,
		"git-chglog": fakeRenderer,
		"git-cliff":  fakeRenderer,
		"ssh":        fakeSSH,
	}
}

// runFakeTool runs the fake that argv[0] names, records the call in the
// calls file of its directory, and reports whether argv[0] named one.
func runFakeTool() (int, bool) {
	name := filepath.Base(os.Args[0])
	fake, ok := fakeTools()[name]
	if !ok {
		return 0, false
	}
	// A fake ends on the signals its caller sends, as the real tool does.
	stopSignals()

	self, err := fakeToolPath(os.Args[0])
	if err == nil {
		err = appendFile(filepath.Join(filepath.Dir(self), "calls"), name+" "+strings.Join(os.Args[1:], " ")+"\n")
	}
	if err != nil {
		return fakeFailed("%v", err), true
	}

	return fake(filepath.Dir(self), os.Args[1:]), true
}

// Resolve the invocation link without allowing PATH to redirect fake state
// into a real tool's directory. Stat follows links but retains their directory.
func fakeToolPath(arg0 string) (string, error) {
	path, err := exec.LookPath(arg0)
	if err != nil {
		return "", err
	}

	self, err := os.Executable()
	if err != nil {
		return "", err
	}

	want, err := os.Stat(self)
	if err != nil {
		return "", err
	}

	got, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	if !os.SameFile(want, got) {
		return "", fmt.Errorf("fake tool %q does not resolve to the test binary: %w", arg0, os.ErrInvalid)
	}

	return path, nil
}

func TestFakeToolPath_RefusesForeignExecutable(t *testing.T) {
	dir := installFakeTools(t, "cosign")
	link := filepath.Join(dir, "cosign")
	if got, err := fakeToolPath(link); err != nil || got != link {
		t.Fatalf("fake link = %q, %v; want %q", got, err, link)
	}

	foreign := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreign, "cosign"), []byte("not the test binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", foreign+string(os.PathListSeparator)+dir)
	if _, err := fakeToolPath("cosign"); err == nil {
		t.Fatal("a PATH entry for a foreign executable must not receive fake state")
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+foreign)
	if got, err := fakeToolPath("cosign"); err != nil || got != link {
		t.Fatalf("fake on PATH = %q, %v; want %q", got, err, link)
	}
}

// installFakeTools links each named tool to the test binary in a new
// directory and returns it, to put at the front of PATH.
func installFakeTools(t *testing.T, names ...string) string {
	t.Helper()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range names {
		if err := os.Symlink(self, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// fakeCalls returns the calls the fakes in dir recorded, one "name args" line
// each; none is the empty string.
func fakeCalls(t *testing.T, dir string) string {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}

	return string(body)
}

// recordEnv writes the fake's environment to the env file of its directory,
// NUL-separated as a value may span lines, for a test that checks what the
// engine passed on.
func recordEnv(dir string) error {
	return os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(os.Environ(), "\x00")), 0o600)
}

// fakeEnv returns the environment a fake in dir recorded.
func fakeEnv(t *testing.T, dir string) []string {
	t.Helper()

	return strings.Split(readFile(t, filepath.Join(dir, "env")), "\x00")
}

func appendFile(path, text string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = file.WriteString(text)

	return errors.Join(err, file.Close())
}

// fakeFailed reports why a fake could not play its part, with the exit code
// that marks it.
func fakeFailed(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "fake %s: %s\n", filepath.Base(os.Args[0]), fmt.Sprintf(format, args...))

	return 125
}
