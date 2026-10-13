// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Package blackbox drives the compiled forge-ci binary as a
// black box. Each Test* function builds a per-scenario fixture (Go
// project, Maven multi-module, GPG keyring, …), invokes the binary
// via os/exec, and asserts on the externally-observable result:
// files produced, exit codes, JSON schemas, signatures verifiable
// by sha256sum / gpg / git verify-tag.
//
// Why a separate package + build tag:
//
//   - The forge-ci unit tests inside internal/... cover internal
//     contracts. They cannot catch failures that only surface when
//     real syft / mvn / gradle / cargo / gpg actually run.
//   - The build tag lets `go test ./...` ignore these during development
//     and opt in for the full suite.
//
// The tag is `blackbox`: that is what this suite is, and what the rest of
// the estate calls a tier that drives the built binary. The engine
// repository invokes this suite by that tag, so the name is an interface
// between two repositories rather than a local detail — changing it again
// means changing both, in that order.
//
// Host isolation:
//
//   - Every test seeds its own scratch dir + GIT_CONFIG_GLOBAL +
//     GIT_CONFIG_SYSTEM + GNUPGHOME so the developer's ~/.gitconfig
//     (e.g. gpg.format=ssh) cannot leak into a GPG test.
//
// Running:
//
//	go test -tags=blackbox -count=1 ./tests/blackbox/...
//	go test -tags=blackbox -count=1 -run TestGoBuild_Reproducible ./tests/blackbox/
package blackbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// binPath is the absolute path to the forge-ci binary built by TestMain.
// Tests use it via exec.CommandContext(binPath, ...).
var binPath string //nolint:gochecknoglobals // intentional: shared by every Test* via TestMain.

// suiteDir is the absolute path to the testsuite root (one level above
// tests/blackbox). Tests resolve fixtures relative to it.
var suiteDir string //nolint:gochecknoglobals // intentional: shared by every Test*.

var errStrictProfile = errors.New("invalid strict blackbox profile") //nolint:gochecknoglobals // Static preflight sentinel.

// suiteCtx ends when the suite is interrupted or terminated. The binaries
// under test run in process groups of their own (see killGroupOnCancel), out
// of reach of the terminal's Ctrl-C, so every invocation is cancelled from it
// and the suite, not the signal, stops them. TestMain releases the handler.
var suiteCtx, stopSignals = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) //nolint:gochecknoglobals // intentional: the suite's one root context.

// A compatible old engine must not accidentally validate the renamed checkout.
// Exercise the public executable identity for both the sibling build and an
// explicit FORGE_CI_TEST_BINARY override, rather than trusting the executable's filename.
func TestBinaryIdentity_HelpNamesForgeCI(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := run(t, runOpts{dir: t.TempDir()}, "--help")
	if code != 0 {
		t.Fatalf("engine help exited %d: %s", code, stderr)
	}

	_, nameSection, found := strings.Cut(stdout, "NAME:")
	fields := strings.Fields(nameSection)
	if !found || len(fields) == 0 || fields[0] != "forge-ci" {
		t.Fatalf("binary under test is not Forge CI: %s", stdout)
	}
}

// TestMain builds the binary once for the whole package unless FORGE_CI_TEST_BINARY names
// an explicit binary under test. The real work is in runSuite so its deferred
// temp-dir cleanup runs before os.Exit (which would skip it).
func TestMain(m *testing.M) {
	code := runSuite(m)

	// After the run, not during: the shortfall is a property of the whole
	// suite, so it belongs next to the verdict rather than scattered among
	// the tests that happened to skip. Stderr because it is a caveat on the
	// result, not part of it.
	reportMissingTools(os.Stderr)

	// Egress violations fail the run even when every test passed: a test
	// that survived a refused fetch by falling back somewhere else is
	// exactly the silent path the audit exists to expose.
	if violations := reportEgress(os.Stderr); violations != 0 && code == 0 {
		code = 3
	}

	os.Exit(code)
}

//nolint:nonamedreturns // a lock-release failure must turn a successful run into a failure.
func runSuite(m *testing.M) (code int) {
	defer stopSignals()
	// The first signal cancels the suite; a second one gets the default
	// behaviour back and ends the run at once.
	context.AfterFunc(suiteCtx, stopSignals)

	release, lockErr := acquireSuiteCacheLock(os.TempDir())
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "blackbox cache: %v\n", lockErr)

		return 2
	}
	defer func() {
		// An interrupted run keeps its lock, as a killed one does: its
		// children were stopped mid-write, so the caches need a look first.
		if suiteCtx.Err() != nil {
			lock := filepath.Join(os.TempDir(), "forge-ci-blackbox.lock")
			fmt.Fprintf(os.Stderr, "blackbox: interrupted; the cache lock %s stays. To start clean: rmdir %s && just clean\n", lock, lock)
			if code == 0 {
				code = 1
			}

			return
		}

		if err := release(); err != nil {
			fmt.Fprintf(os.Stderr, "blackbox cache: release lock: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}()
	// Fixtures are removed before the lock is released, including on the
	// explicit FORGE_CI_TEST_BINARY path. Persistent caches remain available to later runs.
	defer removeSuiteFixtures()

	// Resolve sibling forge-ci checkout. The testsuite lives at
	// .../forge-ci-blackbox-tests/, so the binary source is at ../forge-ci/.
	_, here, _, _ := runtime.Caller(0) //nolint:dogsled // Caller returns (pc, file, line, ok); we need only file.
	suiteDir = filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))

	if err := preflightProfile(); err != nil {
		fmt.Fprintf(os.Stderr, "blackbox preflight: %v\n", err)

		return 2
	}

	// An explicit FORGE_CI_TEST_BINARY override ALWAYS wins over the sibling
	// checkout: compatibility gates point it at the exact candidate binary,
	// and testing a fresh self-build instead would
	// silently validate the wrong artifact.
	if env := os.Getenv("FORGE_CI_TEST_BINARY"); env != "" {
		binPath = env

		return m.Run()
	}

	repo := filepath.Clean(filepath.Join(suiteDir, "..", "forge-ci"))
	if _, err := os.Stat(filepath.Join(repo, "cmd", "forge-ci")); err != nil {
		panic("blackbox: cannot find sibling ../forge-ci/cmd/forge-ci - set FORGE_CI_TEST_BINARY to override")
	}

	tmp, err := os.MkdirTemp("", "forge-ci-int-*")
	if err != nil {
		panic("blackbox: mktemp: " + err.Error())
	}

	defer func() { _ = os.RemoveAll(tmp) }()

	binPath = filepath.Join(tmp, "forge-ci")
	goBin := lookupTool("go")
	if goBin == "" {
		panic("blackbox: go is not on PATH")
	}

	ctx, cancel := context.WithTimeout(suiteCtx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, goBin, "build", "-o", binPath, "./cmd/forge-ci") //nolint:gosec // resolved compiler and hardcoded args.
	cmd.Dir = repo
	cmd.Env = isolatedEnv(nil)
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			panic("blackbox: build forge-ci exceeded 5m")
		}

		panic("blackbox: build forge-ci: " + err.Error())
	}

	return m.Run()
}

// The portable directory lock is also acquired by scripts/clean-cache.sh.
// Never reclaim an existing lock: an interrupted owner needs manual inspection.
func acquireSuiteCacheLock(temporary string) (func() error, error) {
	if !filepath.IsAbs(temporary) {
		return nil, fmt.Errorf("TMPDIR must be absolute: %q: %w", temporary, os.ErrInvalid)
	}
	lock := filepath.Join(temporary, "forge-ci-blackbox.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		return nil, fmt.Errorf("suite or cleanup is active, or a prior run was interrupted; inspect %q: %w", lock, err)
	}

	return func() error { return os.Remove(lock) }, nil
}

func TestSuiteCacheLockSerializesOwners(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	release, err := acquireSuiteCacheLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, acquireErr := acquireSuiteCacheLock(root); !errors.Is(acquireErr, os.ErrExist) {
		t.Fatalf("second owner was admitted: %v", acquireErr)
	}
	if releaseErr := release(); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	release, err = acquireSuiteCacheLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestSuiteCacheLockBlocksCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cache := filepath.Join(root, "forge-ci-blackbox-home")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(cache, "keep")
	if err := os.WriteFile(canary, []byte("active suite"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := acquireSuiteCacheLock(root)
	if err != nil {
		t.Fatal(err)
	}
	runCleanup := func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", filepath.Join(suiteDir, "scripts", "clean-cache.sh"))
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root}
		cmd.WaitDelay = time.Second

		return cmd.Run()
	}
	var exit *exec.ExitError
	if err := runCleanup(); !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("cleanup admitted under Go lock: %v", err)
	}
	if body, err := os.ReadFile(canary); err != nil || string(body) != "active suite" {
		t.Fatalf("active cache changed: %q, %v", body, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := runCleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idle cache not removed: %v", err)
	}
}

func preflightProfile() error {
	return preflightProfileArgs(os.Args[1:])
}

// preflightProfileArgs refuses, before any row runs, a strict run that could
// pass without being the gate: a mistyped profile value, a test selection, or
// an egress audit that did not start. Inside the run, strict turns every skip
// for missing evidence into a failure (skipInOptionalProfilef).
func preflightProfileArgs(args []string) error {
	profile := strings.TrimSpace(os.Getenv(blackboxProfileEnv))
	switch profile {
	case "":
		return nil
	case strictProfileName:
	default:
		return fmt.Errorf("%w: %s must be empty or %q, got %q", errStrictProfile, blackboxProfileEnv, strictProfileName, profile)
	}
	if err := rejectStrictTestSelection(args); err != nil {
		return err
	}
	if err := requireEgressAudit(); err != nil {
		return fmt.Errorf("%w: %w", errStrictProfile, err)
	}

	return nil
}

// TestStrictProfile_RejectsAnUnrecognisedProfileValue pins the switch that
// turns strict enforcement on, in all three of its states.
//
// The dangerous one is the middle: an unrecognised value must be an ERROR, not
// a silent fall-through to "no profile". CI sets this variable to opt in to the
// whole strict contract — no skips, the egress audit and the
// no-test-selection rule — so a typo that quietly
// disabled all of it would leave a green run that proved none of the things the
// run exists to prove, and nothing in the output would say so.
//
// The empty case is equally load-bearing in the other direction: a local `go
// test` must NOT be forced through the strict contract, or the suite becomes
// unrunnable off a CI runner.
func TestStrictProfile_RejectsAnUnrecognisedProfileValue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"unset means no enforcement", "", false},

		// Near misses. Each is a plausible typo, and each must fail loudly
		// rather than silently opting out.
		{"wrong case", "Strict", true},
		{"truncated", "stric", true},
		{"padded with a stray character", "strict1", true},
		{"an unrelated word", "off", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(blackboxProfileEnv, tc.value)

			// No selection flags, and a refused value returns before the
			// egress audit: this isolates the profile-value decision.
			err := preflightProfileArgs(nil)

			if !tc.wantErr {
				if err != nil {
					t.Errorf("profile %q must not enforce anything, got: %v", tc.value, err)
				}

				return
			}

			if err == nil {
				t.Fatalf("profile %q was accepted; a mistyped profile silently disables the whole strict contract", tc.value)
			}

			// The message has to name the value it will accept, or an operator
			// staring at a typo has nothing to compare against.
			if !strings.Contains(err.Error(), strictProfileName) {
				t.Errorf("refusal does not name the accepted value %q: %v", strictProfileName, err)
			}
		})
	}
}

func rejectStrictTestSelection(args []string) error {
	selectionFlags := map[string]struct{}{
		"bench": {},
		"fuzz":  {},
		"list":  {},
		"run":   {},
		"short": {},
		"skip":  {},
	}

	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		name = strings.TrimLeft(name, "-")
		name = strings.TrimPrefix(name, "test.")
		if _, selected := selectionFlags[name]; selected {
			return fmt.Errorf("%w: strict profile forbids test-selection flag %q; run the complete package", errStrictProfile, arg)
		}
	}

	return nil
}

// TestRejectStrictTestSelection_CatchesAllFlagForms drives the strict
// preflight itself, so it pins both the flag parser and that the preflight
// consults it: a filtered strict run must never pass as the gate.
func TestRejectStrictTestSelection_CatchesAllFlagForms(t *testing.T) {
	t.Setenv(blackboxProfileEnv, strictProfileName)

	for _, arg := range []string{
		"-run=TestOne",
		"-test.run=TestOne",
		"-skip=Slow",
		"-test.skip=Slow",
		"-list=Test",
		"-bench=.",
		"-fuzz=FuzzInput",
		"-short",
	} {
		err := preflightProfileArgs([]string{arg})
		if !errors.Is(err, errStrictProfile) || !strings.Contains(err.Error(), "forbids test-selection flag") {
			t.Errorf("strict preflight of %q = %v, want the selection refusal", arg, err)
		}
	}

	if err := rejectStrictTestSelection([]string{"-test.v", "-test.count=1", "-test.timeout=60m"}); err != nil {
		t.Fatalf("non-selecting test flags rejected: %v", err)
	}
}
