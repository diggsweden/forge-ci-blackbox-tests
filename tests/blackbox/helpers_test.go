// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// runOpts customises a single binary invocation.
type runOpts struct {
	dir string            // working directory
	env map[string]string // extra vars for this invocation, on top of the curated base
}

// The sysexits.h-style ladder the CLI exits with, named because the numbers
// carry meaning a reader cannot infer. Success stays a bare 0: `code != 0`
// needs no glossary, and naming it would touch every assertion in the suite
// without making one of them clearer.
//
// TestExitCodes_Matrix in cli_exit_codes_test.go is where the ladder itself is
// pinned; everywhere else these say which class a specific refusal belongs to.
const (
	exitValidation  = 1  // EX_VALIDATION: input present but rejected by a check
	exitUsage       = 2  // EX_USAGE: missing flag, unknown subcommand/option
	exitDataErr     = 65 // EX_DATAERR: an input exists but does not parse
	exitNoInput     = 66 // EX_NOINPUT: a referenced input file is absent
	exitUnavailable = 69 // EX_UNAVAILABLE: a required tool or service is missing
	exitNoPerm      = 77 // EX_NOPERM: release authorisation denied
	exitConfig      = 78 // EX_CONFIG: config readable but its contents are wrong
)

const (
	blackboxProfileEnv = "FORGE_CI_BLACKBOX_PROFILE"
	strictProfileName  = "strict"
)

// Suite deadlines, fixed like the engine's live tier: a deadline too tight
// for a loaded runner is raised here, in one reviewed place.
const (
	// subprocessTimeout bounds one binary or toolchain invocation.
	subprocessTimeout = 10 * time.Minute
	// toolInspectionTimeout bounds one tool version probe and the
	// `mise bin-paths` lookup.
	toolInspectionTimeout = 15 * time.Second
)

func strictProfile() bool {
	return strings.TrimSpace(os.Getenv(blackboxProfileEnv)) == strictProfileName
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// run invokes the forge-ci binary with args, returns combined output + exit code.
//
// Each invocation gets a curated, minimal environment (PATH, an isolated
// HOME, a fixed locale, a test git identity) instead of a copy of the
// developer's shell, so their locale, git config, or GPG keyring can't
// change the result. This only sets the child process's environment; it
// reads and modifies nothing on the host. Per-test additions (GNUPGHOME,
// GITHUB_OUTPUT, …) go via opts.env.
func run(t *testing.T, opts runOpts, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	if suiteCtx.Err() != nil {
		t.Fatalf("run %v: the suite was interrupted", args)
	}

	ctx, cancel := context.WithTimeout(t.Context(), subprocessTimeout)
	defer cancel()
	// An interrupt reaches this process only: the child's own process group
	// is killed through ctx, as on a timeout.
	defer context.AfterFunc(suiteCtx, cancel)()

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = opts.dir
	cmd.Env = isolatedEnv(opts.env)
	killGroupOnCancel(cmd)

	var outBuf, errBuf bytes.Buffer

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if suiteCtx.Err() != nil {
		t.Fatalf("run %v: the suite was interrupted", args)
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("run %v exceeded %s", args, subprocessTimeout)
	}

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run %v: %v", args, err)
	}

	code := cmd.ProcessState.ExitCode()
	if code != 0 && errBuf.Len() > 0 {
		// Shown only when the test fails (or under -v), so a failed assertion on
		// the exit code carries the tool's own explanation.
		t.Logf("forge-ci %s exited %d; stderr:\n%s", strings.Join(args, " "), code, errBuf.String())
	}

	return outBuf.String(), errBuf.String(), code
}

// killGroupOnCancel starts cmd in a process group of its own and, when its
// context ends, kills that whole group instead of the direct child alone: mvn,
// gradle, npm and the binary under test all fork, and a timeout that kills only
// the parent leaves the rest running. WaitDelay bounds the wait for output
// pipes a survivor still holds.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}

		return err
	}
	cmd.WaitDelay = 5 * time.Second
}

// outputOrFatal runs cmd and returns its trimmed stdout, failing the test with
// stderr when it does not succeed. Only stdout is the value: git writes hints
// and warnings to stderr, which must not end up in a compared SHA.
func outputOrFatal(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s (in %s): %v\n%s", strings.Join(cmd.Args, " "), cmd.Dir, err, stderr.String())
	}

	return strings.TrimSpace(string(out))
}

// isolatedEnv builds the environment for one binary invocation: a
// curated minimal base plus the supplied overrides. It hands the child
// process a clean starting point instead of a copy of the developer's
// environment, so their locale, git, and gpg state can't leak into a
// test and skew the result. It only constructs the slice that the caller
// assigns to cmd.Env; it does not touch the host or the parent process's
// own environment, and nothing here is persistent.
//
// HOME is redirected to a dedicated dir under the OS temp dir (see
// isolatedHome). Real toolchain runs cache into $HOME by default
// (~/.m2, ~/.gradle, ~/.cargo, ~/.npm, the go build/module cache), so
// the redirect keeps every one of them out of the developer's real
// home. The isolated home persists across runs, so a warm cache still
// makes reruns fast.
//
// JAVA_HOME, ANDROID_HOME, ANDROID_SDK_ROOT, and RUSTUP_HOME are passed
// through when present so mvn/gradle/cargo can locate their installed
// toolchains; clean-slate environments would silently fail otherwise.
// RUSTUP_HOME additionally falls back to the real home's ~/.rustup,
// because rustup does not export it: it resolves the default from $HOME,
// which this function has already redirected. A rustup-managed cargo then
// finds no toolchain and exits with "could not choose a version of cargo
// to run", which reads like a missing toolchain rather than a redirected
// home. See defaultRustupHome.
// These are install-location pointers, not caches, so isolating them
// would only force needless re-downloads. The host cache vars
// (CARGO_HOME, GOPATH, GOCACHE, GOMODCACHE) are deliberately NOT passed
// through: dropping them lets go/cargo fall back to their defaults under
// the isolated HOME. Maven and Gradle need explicit knobs (MAVEN_ARGS,
// GRADLE_USER_HOME) because the JVM ignores $HOME for user.home.
//
// PATH gets a mise-augmented prefix: many developers manage node /
// java / cargo via mise but haven't activated it in the shell that
// invoked `go test`. `mise bin-paths` adds those installed toolchains.
// defaultRustupHome returns the real home's rustup directory when it exists.
//
// It is only consulted when RUSTUP_HOME is unset, which is the normal state:
// rustup's installer puts its shims on PATH and lets the variable default to
// $HOME/.rustup rather than exporting it. Every other install-location
// passthrough here can rely on the variable being set; this one cannot.
//
// The caller's home is read before constructing the child's redirected HOME;
// isolatedEnv does not change the process environment. Returning "" when absent
// keeps non-rustup hosts (a distro cargo, a mise-managed toolchain) on the
// existing path, where the variable is simply not set.
func defaultRustupHome() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}

	rustup := filepath.Join(home, ".rustup")
	if info, err := os.Stat(rustup); err != nil || !info.IsDir() {
		return ""
	}

	return rustup
}

func isolatedEnv(extra map[string]string) []string {
	procSwaps := os.Getenv("FORGE_CI_PROC_SWAPS")
	if procSwaps == "" {
		procSwaps = defaultNoSwapFixture()
	}

	base := map[string]string{
		"PATH": misePath(os.Getenv("PATH")),
		"HOME": isolatedHome(),
		// Java tools read user.home from the passwd entry, not $HOME. Give
		// Maven CLI arguments through its Maven 3.9+ MAVEN_ARGS mechanism so
		// every invocation uses both the isolated settings and local repo;
		// MAVEN_OPTS only accepts JVM arguments and cannot carry --settings.
		"MAVEN_ARGS": "--settings " + isolatedMavenSettings() +
			" -Dmaven.repo.local=" + filepath.Join(isolatedHome(), ".m2", "repository"),
		"MAVEN_OPTS": isolatedMavenOpts(isolatedHome()),
		// No daemon: one would outlive the run, holding the isolated home.
		"GRADLE_OPTS":      "-Dorg.gradle.daemon=false" + egressJVMProxyOpts(),
		"GRADLE_USER_HOME": filepath.Join(isolatedHome(), ".gradle"),
		// A base for rows that bring no keyring of their own. Deliberately not
		// $HOME/.gnupg: that is GnuPG's default home, whose agent socket is the
		// per-user one (/run/user/<uid>/gnupg), the developer's own gpg-agent.
		"GNUPGHOME":           isolatedGNUPGHome(),
		"LANG":                "C",
		"LC_ALL":              "C",
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_CONFIG_SYSTEM":   os.DevNull,
		"GIT_AUTHOR_NAME":     "Integration Test",
		"GIT_AUTHOR_EMAIL":    "integration@test.example",
		"GIT_COMMITTER_NAME":  "Integration Test",
		"GIT_COMMITTER_EMAIL": "integration@test.example",
		// The caller's explicit /proc/swaps fixture wins. Otherwise use a
		// no-swap fixture so signing tests on developer hosts with swap are
		// not blocked. This redirection is test-only; forge-ci's production
		// workflows do not set it, while this companion's strict workflow uses
		// /dev/null.
		"FORGE_CI_PROC_SWAPS": procSwaps,
		// Containment: cosign uploads every signature to the PUBLIC Rekor
		// transparency log by default, and a Rekor entry is permanent and
		// append-only — a test run cannot take one back. This turns the log off
		// for every binary invocation, so no test can publish, including tests
		// nobody has written yet.
		//
		// It drives both halves — signing writes no entry, verifying stops
		// demanding one — because the engine derives both from this single
		// value. The suite cannot set them inconsistently even by trying.
		//
		// This is the suite-side twin of cosign.New/NewIsolated resolving the
		// same variable: neither side can be opted out of by omission. The
		// trade is real (these signatures give up public verifiability) and is
		// the right one for throwaway test artifacts and the wrong one for
		// anything published — which is why the engine's default is `public`
		// and the suite has to ask for `none` explicitly.
		"FORGE_CI_COSIGN_TRANSPARENCY": "none",
		// The last external dependency in the suite. Turning off the
		// transparency log stops the suite PUBLISHING, and the engine supplies
		// local trust material so a contained signing run makes no proxy-observable
		// cosign HTTP(S) attempt (see release_sign_no_egress_test.go). But keyless
		// VERIFICATION is inherently online: validating a short-lived Fulcio
		// certificate is exactly what Sigstore's trust root is for, so cosign
		// fetches it from tuf-repo-cdn.sigstore.dev when it has none.
		//
		// Point cosign at a local file so no test reaches the network for it,
		// including tests nobody has written yet.
		//
		// The contents are deliberately a placeholder rather than a real root.
		// This suite cannot produce a genuine keyless signature — that needs a
		// live OIDC exchange with a real Fulcio — so no test here verifies one
		// for real. The keyless tests assert what happens BEFORE cosign's trust
		// decision (that forge-ci derived the signing identity from the
		// forge rather than demanding it as a flag), and they already run
		// against a dummy bundle that cannot verify under any trust root. A
		// real root would change none of those assertions and would cost a
		// network round-trip every run.
		"SIGSTORE_ROOT_FILE": defaultSigstoreRootFixture(),
		// syft's update check is not a test input, so disable it rather than
		// widening the egress allowlist.
		"SYFT_CHECK_FOR_APP_UPDATE": "false",
	}

	// Egress audit: every invocation is routed through the recording
	// proxy (see egress_test.go). Applied before the caller's overrides,
	// so a test that must manipulate proxy state (the dead-proxy smoke,
	// a proxy-bypass regression) can still do so explicitly.
	maps.Copy(base, egressProxyEnv())

	for _, name := range []string{"JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "RUSTUP_HOME"} {
		v := os.Getenv(name)
		if v == "" && name == "RUSTUP_HOME" {
			v = defaultRustupHome()
		}

		if v == "" {
			continue
		}

		// JAVA_HOME pointing at a deleted toolchain (common on
		// mise/asdf hosts after an update) makes mvn refuse to
		// start with a misleading error. Drop the var so the
		// java on PATH wins instead.
		if name == "JAVA_HOME" {
			if _, err := os.Stat(filepath.Join(v, "bin", "java")); err != nil {
				continue
			}
		}

		base[name] = v
	}

	maps.Copy(base, extra)

	out := make([]string, 0, len(base))
	for k, v := range base {
		out = append(out, k+"="+v)
	}

	return out
}

// mergeEnv returns base with overlay on top (overlay wins). base may be nil.
func mergeEnv(base, overlay map[string]string) map[string]string {
	out := maps.Clone(base)
	if out == nil {
		out = map[string]string{}
	}

	maps.Copy(out, overlay)

	return out
}

func isolatedMavenOpts(userHome string) string {
	return "-Duser.home=" + userHome + egressJVMProxyOpts()
}

const isolatedMavenSettingsXML = `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
</settings>
`

// isolatedMavenSettings creates the harness-owned settings.xml atomically in
// the persistent isolated home. An explicit --settings argument prevents Maven
// from consulting the account's real ~/.m2/settings.xml.
//
//nolint:gochecknoglobals // one process-wide settings file shared by all Maven invocations.
var isolatedMavenSettings = sync.OnceValue(func() string {
	path := filepath.Join(isolatedHome(), ".maven", "settings.xml")
	mkdirPrivate(filepath.Dir(path), "Maven settings directory")

	if err := writeFileAtomic(path, []byte(isolatedMavenSettingsXML)); err != nil {
		panic("blackbox: cannot install isolated Maven settings: " + err.Error())
	}

	return path
})

// writeFileAtomic writes body to path through a temp file in the same
// directory and a rename, so no reader sees a partial file. CreateTemp makes
// the file 0600.
func writeFileAtomic(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}

	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	_, err = tmp.Write(body)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install %s: %w", filepath.Base(path), err)
	}

	return nil
}

// TestIsolatedEnv_DoesNotLeakTheHostEnvironment is the control under principle
// 7 for the whole suite: every binary invocation gets its environment from
// isolatedEnv, so "these tests are isolated from the host" is true only while
// this function is an ALLOWLIST.
//
// It is one today — `out` is built from `base` alone, and os.Environ() is never
// consulted. That is also exactly the kind of thing a well-meaning change
// undoes: seeding `out` from os.Environ() to "fix" a missing toolchain variable
// would leave every test in this suite passing while quietly restoring host
// contamination, and no existing test would notice. The three tests below check
// what isolatedEnv DOES set; none checks what it must not.
//
// Both directions are asserted, because an isolatedEnv that returned nothing at
// all would satisfy the absence half on its own.
func TestIsolatedEnv_DoesNotLeakTheHostEnvironment(t *testing.T) {
	// A name no allowlist entry matches, and one a careless prefix match might.
	const (
		strayVar   = "BLACKBOX_STRAY_HOST_VAR"
		strayValue = "must-not-reach-the-subprocess"
		lookalike  = "PATH_LOOKALIKE"
	)

	t.Setenv(strayVar, strayValue)
	t.Setenv(lookalike, "also-must-not-leak")

	// A host cache variable the doc comment says is deliberately dropped, so
	// go/cargo fall back to defaults under the isolated HOME.
	t.Setenv("GOCACHE", "/host/gocache")

	env := envMap(isolatedEnv(nil))

	for _, name := range []string{strayVar, lookalike, "GOCACHE"} {
		if got, present := env[name]; present {
			t.Errorf("%s leaked into the isolated environment as %q — isolatedEnv is no longer an allowlist, "+
				"and every host-isolation claim in this suite rests on it", name, got)
		}
	}

	// The other direction: the allowlist still supplies what toolchains need.
	// Without this, an isolatedEnv returning an empty slice would pass above.
	for _, name := range []string{"PATH", "HOME", "GIT_CONFIG_GLOBAL", "FORGE_CI_COSIGN_TRANSPARENCY"} {
		if _, present := env[name]; !present {
			t.Errorf("isolatedEnv dropped %s, which the suite depends on", name)
		}
	}

	// A documented passthrough reaches the subprocess when the host sets it —
	// the exception that makes the allowlist usable on a real machine.
	t.Setenv("RUSTUP_HOME", "/host/rustup")

	if got := envMap(isolatedEnv(nil))["RUSTUP_HOME"]; got != "/host/rustup" {
		t.Errorf("RUSTUP_HOME = %q, want the host value passed through", got)
	}

	// And a caller override wins over the base, which is what every test that
	// passes runOpts{env: ...} relies on.
	if got := envMap(isolatedEnv(map[string]string{"HOME": "/override"}))["HOME"]; got != "/override" {
		t.Errorf("caller override for HOME = %q, want /override", got)
	}

	// $HOME/.gnupg is GnuPG's default home, and the default home's agent is
	// the developer's own.
	if got := env["GNUPGHOME"]; got == "" || got == filepath.Join(env["HOME"], ".gnupg") {
		t.Errorf("GNUPGHOME = %q, want a base home that is not $HOME/.gnupg", got)
	}
}

// A rustup-managed cargo must still find its toolchain once HOME is
// redirected. rustup does not export RUSTUP_HOME, so without the fallback the
// shim resolves ~/.rustup under the isolated home, finds no default toolchain,
// and every cargo probe fails as if the tool were broken.
func TestIsolatedEnv_RustupFallbackUsesCallerHome(t *testing.T) {
	// Resolve the shared tool PATH before changing HOME for this fixture.
	_ = miseBinPaths()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("RUSTUP_HOME", "")
	if _, present := envMap(isolatedEnv(nil))["RUSTUP_HOME"]; present {
		t.Fatal("an absent caller toolchain was exposed to the child")
	}

	rustup := filepath.Join(home, ".rustup")
	if err := os.Mkdir(rustup, 0o700); err != nil {
		t.Fatal(err)
	}

	if got := envMap(isolatedEnv(nil))["RUSTUP_HOME"]; got != rustup {
		t.Errorf("RUSTUP_HOME = %q, want the caller's rustup directory %q", got, rustup)
	}

	// An explicit host value still wins: the fallback fills a gap, it does not
	// override a deliberate choice.
	t.Setenv("RUSTUP_HOME", "/host/rustup")

	if got := envMap(isolatedEnv(nil))["RUSTUP_HOME"]; got != "/host/rustup" {
		t.Errorf("RUSTUP_HOME = %q, want the host value to win over the fallback", got)
	}
}

func TestIsolatedEnv_PinsPrivateMavenSettings(t *testing.T) {
	t.Parallel()

	settings := isolatedMavenSettings()
	info, err := os.Stat(settings)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("settings.xml mode = %#o, want 0600", got)
	}

	var doc struct {
		XMLName xml.Name `xml:"settings"`
	}
	if err := xml.Unmarshal([]byte(readFile(t, settings)), &doc); err != nil {
		t.Fatalf("isolated settings.xml is not valid XML: %v", err)
	}

	env := envMap(isolatedEnv(nil))
	wantArgs := "--settings " + settings + " -Dmaven.repo.local=" + filepath.Join(isolatedHome(), ".m2", "repository")
	if env["MAVEN_ARGS"] != wantArgs {
		t.Errorf("MAVEN_ARGS = %q, want %q", env["MAVEN_ARGS"], wantArgs)
	}

	// The egress audit appends the JVM proxy properties (empty when the
	// audit is off); the user.home pin must still lead the value.
	if want := isolatedMavenOpts(isolatedHome()); env["MAVEN_OPTS"] != want {
		t.Errorf("MAVEN_OPTS = %q, want %q", env["MAVEN_OPTS"], want)
	}

	override := isolatedMavenOpts(filepath.Join(t.TempDir(), "hostile-home"))
	if got := envMap(isolatedEnv(map[string]string{"MAVEN_OPTS": override}))["MAVEN_OPTS"]; got != override {
		t.Errorf("overridden MAVEN_OPTS = %q, want %q", got, override)
	}
}

func TestIsolatedEnv_HonorsProcSwapsOverride(t *testing.T) {
	t.Run("default fixture", func(t *testing.T) {
		t.Setenv("FORGE_CI_PROC_SWAPS", "")
		if got := envMap(isolatedEnv(nil))["FORGE_CI_PROC_SWAPS"]; got != defaultNoSwapFixture() {
			t.Errorf("FORGE_CI_PROC_SWAPS = %q, want default fixture %q", got, defaultNoSwapFixture())
		}
	})

	t.Run("explicit fixture", func(t *testing.T) {
		override := filepath.Join(t.TempDir(), "explicit-swaps")
		t.Setenv("FORGE_CI_PROC_SWAPS", override)
		if got := envMap(isolatedEnv(nil))["FORGE_CI_PROC_SWAPS"]; got != override {
			t.Errorf("FORGE_CI_PROC_SWAPS = %q, want explicit fixture %q", got, override)
		}
	})
}

// TestMaven_IgnoresAmbientUserSettings runs only Maven's validate lifecycle
// phase, which needs no project dependencies or plugins. A deliberately broken
// ambient settings.xml would make Maven fail if the explicit isolated settings
// were ever dropped.
func TestMaven_IgnoresAmbientUserSettings(t *testing.T) {
	requireTool(t, "mvn")

	hostileHome := t.TempDir()
	hostileM2 := filepath.Join(hostileHome, ".m2")
	if err := os.MkdirAll(hostileM2, 0o700); err != nil {
		t.Fatal(err)
	}

	hostileSettings := filepath.Join(hostileM2, "settings.xml")
	if err := os.WriteFile(hostileSettings, []byte(`<settings><broken>`), 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example.test</groupId>
  <artifactId>settings-isolation</artifactId>
  <version>1.0.0</version>
</project>
`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}

	mavenOpts := isolatedMavenOpts(hostileHome)
	cmd := toolCommand(t, project, map[string]string{"MAVEN_OPTS": mavenOpts},
		"mvn", "-X", "-B", "-ntp", "validate")
	if got := envMap(cmd.Env)["MAVEN_OPTS"]; got != mavenOpts {
		t.Fatalf("final Maven command MAVEN_OPTS = %q, want %q", got, mavenOpts)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Maven read hostile ambient settings or validate failed: %v\n%s", err, output)
	}

	text := string(output)
	if !strings.Contains(text, isolatedMavenSettings()) {
		t.Errorf("Maven debug output does not name isolated settings %s\n%s", isolatedMavenSettings(), text)
	}

	if strings.Contains(text, hostileSettings) {
		t.Errorf("Maven consulted hostile ambient settings %s\n%s", hostileSettings, text)
	}
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))

	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		out[name] = value
	}

	return out
}

// copyTree clones src to dst (called per-test so fixtures stay
// pristine). Generated directories named in the suite .gitignore are
// pruned, while committed source and .forge-ci inputs are preserved.
// File modes carry over so executable bits on `gradlew` etc. survive.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()

	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != src && generatedFixtureDir(d.Name()) {
			return fs.SkipDir
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}

			return os.Symlink(link, target)
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}

			return copyFile(path, target, info.Mode().Perm())
		}
	})
	if err != nil {
		t.Fatalf("copy %s → %s: %v", src, dst, err)
	}

	return dst
}

func generatedFixtureDir(name string) bool {
	switch name {
	case "target", "build", ".gradle", "bin", "node_modules", "dist":
		return true
	default:
		return false
	}
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)

	return err
}

// fixture resolves a path under the testsuite root (the directory
// containing the ecosystem hello-world projects).
func fixture(name string) string { return filepath.Join(suiteDir, "fixtures", name) }

// sha256File returns the hex SHA256 of path. Fails the test on error.
func sha256File(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// requireTool skips the test if the named command is not on PATH.
// Lets the suite run in environments missing optional toolchains
// (npm, cyclonedx-gomod, etc.) without failing.
//
// Looks up the binary against the *augmented* PATH (mise-managed install
// directories first, followed by the host PATH) so a clean `go test` invocation
// can still find node / java / cargo etc. when mise hasn't been
// activated in the calling shell.
func requireTool(t *testing.T, name string) {
	t.Helper()

	if lookupTool(name) == "" {
		skipInOptionalProfilef(t, "%s is not on PATH", name)
	}
}

// requireWorkingTool is requireTool plus a smoke run: some runners ship
// proxy shims (e.g. rustup's cargo on ubuntu-26.04) that are on PATH and
// executable but fail at runtime because no default toolchain is set.
// Running the tool with the given args catches that as "absent" rather
// than letting the test fail with a cryptic error from the shim.
func requireWorkingTool(t *testing.T, name string, args ...string) {
	t.Helper()

	path := lookupTool(name)
	if path == "" {
		skipInOptionalProfilef(t, "%s is not on PATH", name)
	}

	cmd := exec.CommandContext(t.Context(), path, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		skipInOptionalProfilef(t, "%s is on PATH but failed to run: %v\n%s", name, err, out)
	}
}

func skipInOptionalProfilef(t *testing.T, format string, args ...any) {
	t.Helper()

	reason := fmt.Sprintf(format, args...)
	if err := strictSkipError(reason); err != nil {
		t.Fatal(err)
	}

	// The skip is evidence the run did not produce, so it joins the
	// NOT-PROVEN tally TestMain reports once at the end. The reason is the
	// tally key, so it names the missing prerequisite and nothing
	// run-specific.
	recordMissingTool(reason)

	t.Skip(reason)
}

func strictSkipError(reason string) error {
	if strictProfile() {
		return fmt.Errorf("%w: cannot skip required evidence: %s", errStrictProfile, reason)
	}

	return nil
}

func TestStrictSkipError_ForbidsSkipOnlyInStrictProfile(t *testing.T) {
	t.Run("optional profile permits skip", func(t *testing.T) {
		t.Setenv(blackboxProfileEnv, "")
		if err := strictSkipError("fixture unavailable"); err != nil {
			t.Fatalf("optional profile skip = %v", err)
		}
	})

	t.Run("strict profile rejects skip", func(t *testing.T) {
		t.Setenv(blackboxProfileEnv, strictProfileName)
		for _, reason := range []string{
			"Gradle wrapper unavailable",
			"Java path cannot be resolved",
			"Git lacks SHA-256 object-format support",
		} {
			err := strictSkipError(reason)
			if err == nil || !errors.Is(err, errStrictProfile) || !strings.Contains(err.Error(), reason) {
				t.Errorf("strict profile skip %q = %v", reason, err)
			}
		}
	})
}

// missingTools counts the tests each absent tool took with it. Go reports a
// skip next to the test that skipped, which scrolls past among a hundred
// passes, and the run still ends in "ok" -- so a suite that proved most of its
// ground and one that proved almost none read identically at the only place
// anyone looks. Recording here lets TestMain state the shortfall once, at the
// end, where the verdict is read.
type toolTally struct {
	mu     sync.Mutex
	counts map[string]int
}

//nolint:gochecknoglobals // suite-wide tally: skipInOptionalProfilef records, TestMain summarises.
var missingTools = toolTally{counts: map[string]int{}}

func recordMissingTool(name string) {
	missingTools.mu.Lock()
	defer missingTools.mu.Unlock()

	missingTools.counts[name]++
}

// renderMissingTools returns what the run did not prove, or "" when it proved
// everything it set out to: a complete run should not have to say so.
//
// This reports rather than fails in the default developer profile so a bare
// machine still runs what it can. The strict profile fails at the skip
// instead, so a strict run never reaches this with a shortfall.
func renderMissingTools() string {
	missingTools.mu.Lock()
	defer missingTools.mu.Unlock()

	if len(missingTools.counts) == 0 {
		return ""
	}

	names := make([]string, 0, len(missingTools.counts))
	skipped := 0

	for name, count := range missingTools.counts {
		names = append(names, name)
		skipped += count
	}

	slices.Sort(names)

	var out strings.Builder

	// Each key is a skip reason from skipInOptionalProfilef: evidence the
	// run did not produce.
	fmt.Fprintf(&out, "%d test(s) skipped for %d unproven cause(s):\n",
		skipped, len(names))

	for _, name := range names {
		fmt.Fprintf(&out, "  %-24s %d test(s)\n", name, missingTools.counts[name])
	}

	return out.String()
}

// reportMissingTools publishes the shortfall to both places it can be read.
//
// Stderr alone is not enough, and that is the whole reason this exists: with a
// passing package and no -v, `go test` prints "ok" and discards everything the
// binary wrote. The CI workflow runs without -v, so a stderr-only report would
// be invisible in exactly the run it was written for. GITHUB_STEP_SUMMARY is
// a file, outside that buffering, and is already where this job publishes its
// result table.
func reportMissingTools(out io.Writer) {
	report := renderMissingTools()
	if report == "" {
		return
	}

	_, _ = fmt.Fprintf(out, "\nNOT PROVEN: %s", report)

	summary := os.Getenv("GITHUB_STEP_SUMMARY")
	if summary == "" {
		return
	}

	if err := appendStepSummary(summary, "Not proven", report); err != nil {
		_, _ = fmt.Fprintf(out, "cannot write GITHUB_STEP_SUMMARY: %v\n", err)
	}
}

// appendStepSummary appends a titled text block to the step summary at
// path. Appending, not truncating: the workflow writes its own table to
// this file afterwards, and a truncating open would drop whichever ran
// second.
func appendStepSummary(path, title, body string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(file, "\n### %s\n\n```text\n%s```\n", title, body)

	return errors.Join(err, file.Close())
}

// configPlanJSON runs `--json config parse-artifacts` in dir against
// .forge-ci/artifacts.yml and returns the plan JSON it carries.
func configPlanJSON(t *testing.T, dir string) string {
	t.Helper()

	stdout, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "--json", "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("config parse-artifacts exit %d\nstderr: %s", code, stderr)
	}

	return unwrapConfigPlan(t, stdout)
}

// unwrapConfigPlan returns the plan from the parse-artifacts envelope,
// which carries it as an escaped JSON string: {"config-plan-json":"…"}.
func unwrapConfigPlan(t *testing.T, stdout string) string {
	t.Helper()

	var outer struct {
		ConfigPlanJSON string `json:"config-plan-json"`
	}
	decodeJSON(t, "config plan envelope", stdout, &outer)

	if outer.ConfigPlanJSON == "" {
		t.Fatalf("config parse-artifacts emitted no config-plan-json:\n%s", stdout)
	}

	return outer.ConfigPlanJSON
}

// lookupTool returns the absolute path to `name` searching the
// augmented PATH; empty string when not found.
func lookupTool(name string) string {
	augmented := misePath(os.Getenv("PATH"))
	for _, dir := range filepath.SplitList(augmented) {
		if dir == "" {
			continue
		}

		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}

	return ""
}

// readFile reads path, failing the test on error.
func readFile(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(body)
}

// fileExists reports whether path is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.Mode().IsRegular()
}

// defaultNoSwapFixture returns a path to a process-wide /proc/swaps
// fixture that reports no active swap. Computed lazily so tests that
// run before the helper is touched don't see a partial file. Same
// file is reused across the process — it's just header-only data.
//
// Process-wide fixtures are built once and shared by every invocation, so they
// cannot use t.TempDir(): no single test owns them. That left each one leaking
// a file per run into the OS temp dir, accumulating silently for as long as the
// suite has existed.
//
// suiteFixture records such a file for removeSuiteFixtures, which runSuite
// defers. Register anything the suite creates and does not want to keep. Do NOT
// register the deliberately persistent state — isolatedHome and buildahRoot are
// warm caches that exist precisely to survive between runs.
//
//nolint:gochecknoglobals // process-wide fixture registry, drained by TestMain.
var (
	suiteFixtureMu    sync.Mutex
	suiteFixturePaths []string
)

func suiteFixture(path string) string {
	suiteFixtureMu.Lock()
	defer suiteFixtureMu.Unlock()

	suiteFixturePaths = append(suiteFixturePaths, path)

	return path
}

// removeSuiteFixtures removes registered files without recursive deletion.
// An already absent file is success; other failures must remain visible.
func removeSuiteFixtures() error {
	suiteFixtureMu.Lock()
	defer suiteFixtureMu.Unlock()

	var failures []error
	for _, path := range suiteFixturePaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove suite fixture: %w", err))
		}
	}

	suiteFixturePaths = nil

	return errors.Join(failures...)
}

//nolint:gochecknoglobals // process-wide cached file path.
var defaultNoSwapFixture = sync.OnceValue(func() string {
	f, err := os.CreateTemp("", "forge-ci-no-swap-*")
	if err != nil {
		panic("integration: cannot create no-swap fixture: " + err.Error())
	}

	// Header-only /proc/swaps body. The kernel always writes
	// this header even when no swap is configured.
	if _, err := f.WriteString("Filename\tType\tSize\tUsed\tPriority\n"); err != nil {
		panic("integration: cannot write no-swap fixture: " + err.Error())
	}

	if err := f.Close(); err != nil {
		panic("integration: cannot close no-swap fixture: " + err.Error())
	}

	return suiteFixture(f.Name())
})

// Sigstore trust-root containment: see the SIGSTORE_ROOT_FILE entry in
// isolatedEnv for why a placeholder is the right value here.
//
//nolint:gochecknoglobals // process-wide fixture path, resolved once.
var defaultSigstoreRootFixture = sync.OnceValue(func() string {
	f, err := os.CreateTemp("", "forge-ci-sigstore-root-*.pem")
	if err != nil {
		panic("integration: cannot create sigstore root fixture: " + err.Error())
	}

	// Not a usable CA, and not meant to be: its only job is to stop cosign
	// deciding it must go and fetch one. Anything that verifies against it
	// was going to fail on its dummy bundle regardless.
	if _, err := f.WriteString(
		"# forge-ci black-box tests: placeholder trust root.\n" +
			"# Present so cosign does not fetch tuf-repo-cdn.sigstore.dev.\n"); err != nil {
		panic("integration: cannot write sigstore root fixture: " + err.Error())
	}

	if err := f.Close(); err != nil {
		panic("integration: cannot close sigstore root fixture: " + err.Error())
	}

	return suiteFixture(f.Name())
})

// Rekor containment. cosign signs against the public Sigstore config unless
// told otherwise, which publishes a permanent, append-only, publicly queryable
// entry for every signature — including the throwaway ones a test suite makes,
// on every run, in CI, and in forgejo-ci's vendor gate. cosign 3.x deprecated
// --tlog-upload in favour of a signing-config file with no transparency-log
// service, and that file is what this builds: once per process, reused by every
// invocation via isolatedEnv.
//
// Generated by cosign itself rather than hand-written, so the config's media
// type and shape stay whatever the installed cosign understands.
//
// misePath returns base augmented with every directory reported by
// `mise bin-paths` that isn't already in base. Result: a clean
// shell `go test` invocation still sees mise-managed toolchains
// (node, java, cargo, …) without requiring `mise activate` in the
// caller's environment.
//
// Failures (mise not installed, command error) silently fall back
// to the original PATH so the helper never blocks a test that
// doesn't need mise.
func misePath(base string) string {
	seen := map[string]bool{}
	for _, dir := range filepath.SplitList(base) {
		seen[dir] = true
	}

	var add []string

	for _, dir := range miseBinPaths() {
		if !seen[dir] {
			add = append(add, dir)
			seen[dir] = true
		}
	}

	if len(add) == 0 {
		return base
	}

	return strings.Join(append(add, base), string(os.PathListSeparator))
}

// miseBinPaths runs `mise bin-paths` once per process, resolving mise against
// the PATH in effect at the first call, and returns nil when that fails.
//
//nolint:gochecknoglobals // memoised once per process.
var miseBinPaths = sync.OnceValue(func() []string {
	// MISE_OFFLINE: mise contacts its versions host on an ordinary
	// invocation, so probing for toolchains was the suite's last piece of
	// unconditional egress — one call per run, before any test did
	// anything. This probe only reads local install dirs, so offline
	// changes nothing about what it finds (verified: same 59 paths), and
	// no test here installs a toolchain through mise.
	ctx, cancel := context.WithTimeout(context.Background(), toolInspectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mise", "bin-paths")
	cmd.Env = append(os.Environ(), "MISE_OFFLINE=1")
	cmd.WaitDelay = time.Second

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var dirs []string

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			dirs = append(dirs, line)
		}
	}

	return dirs
})

// toolCommand builds a context-bound command for an external tool, resolved
// against the suite PATH and run in the curated isolated environment.
func toolCommand(t *testing.T, dir string, env map[string]string, name string, args ...string) *exec.Cmd {
	t.Helper()

	if suiteCtx.Err() != nil {
		t.Fatalf("tool %s: the suite was interrupted", name)
	}

	bin := name
	if !strings.ContainsRune(name, os.PathSeparator) {
		bin = lookupTool(name)
		if bin == "" {
			t.Fatalf("resolve tool %s against isolated PATH", name)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), subprocessTimeout)
	stop := context.AfterFunc(suiteCtx, cancel)
	t.Cleanup(func() {
		stop()
		cancel()
	})

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = isolatedEnv(env)
	killGroupOnCancel(cmd)

	return cmd
}

// runTool invokes a plain external binary (npm, mvn, cargo, …) in the given
// directory and returns its stdout, stderr and exit code. Used by tests that
// materialise real artifacts (npm pack, mvn package, cargo build) before
// pointing forge-ci at them.
func runTool(t *testing.T, dir, name string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	return runToolEnv(t, dir, nil, name, args...)
}

func runToolEnv(t *testing.T, dir string, env map[string]string, name string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := toolCommand(t, dir, env, name, args...)

	var outBuf, errBuf bytes.Buffer

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// A context kill surfaces as "signal: killed"; Cancel runs only then.
	var timedOut bool

	killGroup := cmd.Cancel
	cmd.Cancel = func() error {
		timedOut = true

		return killGroup()
	}

	err := cmd.Run()
	if timedOut {
		t.Fatalf("run %s %v exceeded %s", name, args, subprocessTimeout)
	}

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run %s %v: %v", name, args, err)
	}

	code := cmd.ProcessState.ExitCode()
	if code != 0 && errBuf.Len() > 0 {
		t.Logf("%s %s exited %d; stderr:\n%s", name, strings.Join(args, " "), code, errBuf.String())
	}

	return outBuf.String(), errBuf.String(), code
}

// suiteCacheName names the per-user directory that holds the persistent
// caches and their lock on macOS. scripts/clean-cache.sh derives the same path.
const suiteCacheName = "forge-ci-blackbox-tests"

// cacheRoot returns the directory that holds the persistent caches and their
// lock: TMPDIR on Linux, ~/Library/Caches/forge-ci-blackbox-tests on macOS.
// macOS's dirhelper deletes files older than three days under TMPDIR but
// keeps the directories, so unpacked archives (cargo sources, Gradle caches)
// vanish while the completion markers the toolchains trust survive.
func cacheRoot() (string, error) {
	root := os.TempDir()
	if runtime.GOOS == "darwin" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("locate the user cache directory: %w", err)
		}

		root = filepath.Join(dir, suiteCacheName)
	}

	return root, nil
}

// suiteCacheRoot is cacheRoot resolved once. The macOS root belongs to the
// suite alone, so it gets the same ownership checks as the caches; the shared
// Linux temp root is used as it is. acquireSuiteCacheLock refuses a relative
// root before any cache is created.
//
//nolint:gochecknoglobals // process-wide cache root, resolved once.
var suiteCacheRoot = sync.OnceValue(func() string {
	root, err := cacheRoot()
	if err != nil {
		panic("blackbox: " + err.Error())
	}

	if runtime.GOOS == "darwin" && filepath.IsAbs(root) {
		mkdirPrivate(root, "cache root")
	}

	return root
})

// Toolchain cache isolation. Real toolchain runs (mvn, gradle, cargo,
// npm, go) cache into $HOME by default. isolatedHome gives them a
// dedicated home under the suite cache root so those caches never land in
// the developer's real home. The dir is process-wide and persistent, so the
// base image, gradle distribution, downloaded deps, and module cache are
// fetched once and reused across a run. Use the coordinated `just clean` route.
//
//nolint:gochecknoglobals // process-wide home path, resolved once.
var isolatedHome = sync.OnceValue(func() string {
	dir := filepath.Join(suiteCacheRoot(), "forge-ci-blackbox-home")
	mkdirPrivate(dir, "isolated HOME")

	return dir
})

// isolatedGNUPGHome is the base GNUPGHOME under the isolated home. It exists
// up front because gpg creates only its default home by itself.
//
//nolint:gochecknoglobals // process-wide GnuPG home path, resolved once.
var isolatedGNUPGHome = sync.OnceValue(func() string {
	dir := filepath.Join(isolatedHome(), "gnupg-home")
	mkdirPrivate(dir, "isolated GNUPGHOME")

	return dir
})

// mkdirPrivate creates a well-known cache directory and refuses to use one it
// does not own or that others can write to.
//
// The path is fixed and predictable by design -- a warm cache across runs is
// what keeps the suite usable -- which on a shared machine means anyone can
// create it first. What lands inside is not inert: .m2, .gradle, .cargo and
// the module cache hold code that later gets linked into the artifacts these
// tests then sign and verify. os.MkdirAll is happy to hand back a directory
// somebody else made, so the ownership and mode have to be checked rather than
// assumed.
func mkdirPrivate(path, label string) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		panic("blackbox: cannot create " + label + ": " + err.Error())
	}

	info, err := os.Lstat(path)
	if err != nil {
		panic("blackbox: cannot stat " + label + ": " + err.Error())
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		panic("blackbox: " + label + " " + path + " is not a real directory; refusing to use it")
	}

	if info.Mode().Perm()&0o022 != 0 {
		panic(fmt.Sprintf("blackbox: %s %s is group- or world-writable (%#o); "+
			"another user could plant a dependency the build then trusts. Remove it and re-run.",
			label, path, info.Mode().Perm()))
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		panic(fmt.Sprintf("blackbox: %s %s is owned by uid %d, not %d; "+
			"refusing to reuse another user's cache. Remove it and re-run.",
			label, path, stat.Uid, os.Getuid()))
	}
}

// Buildah storage isolation. The buildah-driven tests build into a
// dedicated graphroot under the suite cache root instead of the developer's
// default rootless container storage, so test images and layers never
// appear in `buildah images` on the host. The root is process-wide, so
// the base image is pulled once and reused across the buildah tests in a
// run rather than re-pulled per test. Use the coordinated `just clean` route.
//
//nolint:gochecknoglobals // process-wide storage path, resolved once.
var buildahRoot = sync.OnceValue(func() string {
	root := filepath.Join(suiteCacheRoot(), "forge-ci-blackbox-buildah")
	mkdirPrivate(root, "buildah storage root")

	return root
})

// buildahStorageArgs returns the global flags that point buildah at the
// isolated store. Returned fresh each call so callers can append safely.
func buildahStorageArgs() []string {
	root := buildahRoot()

	return []string{
		"--root", filepath.Join(root, "storage"),
		"--runroot", filepath.Join(root, "run"),
	}
}

// runBuildah runs buildah with the isolated storage root, so it never
// writes to the host's default container storage. Storage flags are
// global and must precede the subcommand.
func runBuildah(t *testing.T, dir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	return runTool(t, dir, "buildah", append(buildahStorageArgs(), args...)...)
}

// globMust panics only when a programmer introduces a malformed hard-coded
// pattern. Callers remain responsible for asserting the number of matches.
func globMust(dir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		panic("invalid test glob " + pattern + ": " + err.Error())
	}

	return matches
}

// assertChecksumManifestLists fails for each name without its own entry in
// the sha256sum manifest at path. Names match whole base names, so a name that
// is only a substring of another entry does not count; sha256sum --check
// separately proves the recorded paths and digests.
func assertChecksumManifestLists(t *testing.T, path string, names ...string) {
	t.Helper()

	entries := checksumManifestNames(t, path)
	for _, name := range names {
		if !slices.Contains(entries, name) {
			t.Errorf("checksum manifest %s has no entry for %s; entries: %v", filepath.Base(path), name, entries)
		}
	}
}

// checksumManifestNames returns the base name of every entry in a sha256sum
// manifest, failing the test on a line that is not "<digest>  <path>".
func checksumManifestNames(t *testing.T, path string) []string {
	t.Helper()

	var names []string

	for line := range strings.Lines(readFile(t, path)) {
		digest, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "  ")
		if !ok || len(digest) != sha256.Size*2 || name == "" {
			t.Fatalf("malformed checksum manifest line %q in %s", line, path)
		}

		names = append(names, filepath.Base(name))
	}

	return names
}

// assertContains fails the test when haystack lacks needle.
func assertContains(t *testing.T, label, haystack, needle string) {
	t.Helper()

	if !strings.Contains(haystack, needle) {
		t.Errorf("%s: missing %q in output:\n%s", label, needle, haystack)
	}
}

type dockerCredentialValue struct {
	registry string
	field    string
	value    string
}

func dockerConfigCredentialValues(body []byte) ([]dockerCredentialValue, error) {
	var config struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
			Password      string `json:"password"`
			RegistryToken string `json:"registrytoken"`
			Username      string `json:"username"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("parse Docker config: %w", err)
	}

	var values []dockerCredentialValue
	for registry, auth := range config.Auths {
		if auth.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
			if err != nil {
				return nil, fmt.Errorf("decode auth for %s: %w", registry, err)
			}
			values = append(values, dockerCredentialValue{registry: registry, field: "auth", value: string(decoded)})
		}
		for field, value := range map[string]string{
			"identitytoken": auth.IdentityToken,
			"password":      auth.Password,
			"registrytoken": auth.RegistryToken,
			"username":      auth.Username,
		} {
			if value != "" {
				values = append(values, dockerCredentialValue{registry: registry, field: field, value: value})
			}
		}
	}

	return values, nil
}

func assertDockerConfigDoesNotContainCredentials(t *testing.T, path string, secrets ...string) {
	t.Helper()

	values, err := dockerConfigCredentialValues([]byte(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		for _, secret := range secrets {
			if secret != "" && strings.Contains(value.value, secret) {
				t.Errorf("Docker config %s field %s for %s contains a forbidden credential", path, value.field, value.registry)
			}
		}
	}
}

// assertSBOMSubject asserts the SBOM at path names want as the artifact it
// describes — the SPDX document name, or the CycloneDX metadata.component name.
//
// assertValidCycloneDXJSON and assertValidSPDXJSON prove a file is a real BOM
// of its format; neither says WHAT it is a BOM of. An SBOM generated against
// the wrong artifact, or against a stale one left in the working directory, is
// a valid document making a false claim, and a downstream scanner reads it as
// authoritative for the thing it was published beside.
//
// The CycloneDX XML path already checks this (assertCycloneDXXMLComponent);
// this is the same assertion for the two JSON formats, which is where syft's
// analyzed-artifact layer lands.
func assertSBOMSubject(t *testing.T, path, want string) {
	t.Helper()

	body := readFile(t, path)

	var doc struct {
		Name     string `json:"name"` // SPDX: document name
		Metadata struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"` // CycloneDX: the component described
	}

	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("parse SBOM %s: %v", path, err)
	}

	got := doc.Name
	if got == "" {
		got = doc.Metadata.Component.Name
	}

	if got != want {
		t.Errorf("%s describes %q, want %q — the SBOM names a different artifact than the one it was generated for", path, got, want)
	}
}

// assertValidCycloneDXJSON parses a CycloneDX JSON SBOM at path and
// asserts it is a well-formed document: the format header is present and
// specVersion is a 1.x release. It deliberately does NOT require a
// component list, since that depends on whether the scanned fixture has
// dependencies; callers whose fixture is known to pull deps assert the
// component count themselves. This is the shared "is this a real BOM,
// not an empty or truncated file" gate.
func assertValidCycloneDXJSON(t *testing.T, path string) {
	t.Helper()

	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}

	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatalf("parse CycloneDX %s: %v", path, err)
	}

	if doc.BomFormat != "CycloneDX" {
		t.Errorf("%s: bomFormat = %q, want CycloneDX", path, doc.BomFormat)
	}

	if !strings.HasPrefix(doc.SpecVersion, "1.") {
		t.Errorf("%s: specVersion = %q, want 1.x", path, doc.SpecVersion)
	}
}

// assertValidSPDXJSON parses an SPDX JSON SBOM at path and asserts the
// document identity fields are present (version in the SPDX-2.x line and
// a non-empty SPDXID). Same rationale as assertValidCycloneDXJSON: prove
// the file is a real SPDX document, not just present.
func assertValidSPDXJSON(t *testing.T, path string) {
	t.Helper()

	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
	}

	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatalf("parse SPDX %s: %v", path, err)
	}

	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-2.") {
		t.Errorf("%s: spdxVersion = %q, want SPDX-2.x", path, doc.SPDXVersion)
	}

	if doc.SPDXID == "" {
		t.Errorf("%s: SPDXID empty", path)
	}
}

// assertCycloneDXXMLComponent parses a CycloneDX XML SBOM (what
// cargo-cyclonedx emits) at path and asserts the root element, the
// CycloneDX namespace, and the primary component name in <metadata>.
// The namespace is checked by prefix so it stays valid across the
// CycloneDX 1.x schema revisions.
func assertCycloneDXXMLComponent(t *testing.T, path, wantComponent string) {
	t.Helper()

	var doc struct {
		XMLName  xml.Name
		Metadata struct {
			Component struct {
				Name string `xml:"name"`
			} `xml:"component"`
		} `xml:"metadata"`
	}

	if err := xml.Unmarshal([]byte(readFile(t, path)), &doc); err != nil { //nolint:musttag // xml.Name root field is idiomatically untagged; we read .Local manually.
		t.Fatalf("parse CycloneDX XML %s: %v", path, err)
	}

	if doc.XMLName.Local != "bom" {
		t.Errorf("%s: root element = %q, want bom", path, doc.XMLName.Local)
	}

	if !strings.HasPrefix(doc.XMLName.Space, "http://cyclonedx.org/schema/bom/") {
		t.Errorf("%s: namespace = %q, want CycloneDX schema", path, doc.XMLName.Space)
	}

	if doc.Metadata.Component.Name != wantComponent {
		t.Errorf("%s: metadata component = %q, want %q", path, doc.Metadata.Component.Name, wantComponent)
	}
}
