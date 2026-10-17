// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Locks the swap-refusal contract through the real CLI: `release sign` MUST
// exit EX_CONFIG (78) when /proc/swaps reports an active swap area,
// unless the operator passes --debug-allow-swap. The swap state is
// injected via FORGE_CI_PROC_SWAPS (a test-only knob that
// redirects the reader, NOT a policy override).

package blackbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// procSwapsWith returns a path to a synthetic /proc/swaps body.
// header-only → no swap; one extra line → swap on.
func procSwapsWith(t *testing.T, swapOn bool) string {
	t.Helper()

	body := "Filename\tType\tSize\tUsed\tPriority\n"
	if swapOn {
		body += "/dev/sda2\tpartition\t2097148\t0\t-2\n"
	}

	path := filepath.Join(t.TempDir(), "swaps")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// swapEnv is the signing environment plus a synthetic /proc/swaps reporting
// swap on or off — the one variable these tests actually vary.
func swapEnv(t *testing.T, key gpgKey, swapOn bool) map[string]string {
	t.Helper()

	// The engine reads swap state, and this override, only in its Linux build;
	// elsewhere it reports undetermined state, covered by the soft-pass test.
	if runtime.GOOS != "linux" {
		skipInOptionalProfilef(t, "swap policy reads Linux /proc/swaps; run on a native Linux host")
	}

	env := key.signingEnv(t)
	env["FORGE_CI_PROC_SWAPS"] = procSwapsWith(t, swapOn)

	return env
}

// TestSwapRefusal_ReleaseSignRefusesWith78 verifies that `release
// sign` exits with EX_CONFIG (78) and the actionable error message
// when /proc/swaps reports an active swap area.
func TestSwapRefusal_ReleaseSignRefusesWith78(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: swapEnv(t, key, true),
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")

	if code != exitConfig { // EX_CONFIG (sysexits.h)
		t.Errorf("expected EX_CONFIG=78 with swap on, got %d\nstderr: %s", code, stderr)
	}

	for _, want := range []string{
		"swap is enabled",
		"swapoff",
		"hosted runner",
		"Sigstore",
		"KMS",
	} {
		assertContains(t, "operator guidance", stderr, want)
	}

	// The signature must NOT have been produced.
	if fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("policy was bypassed — signature was created despite swap refusal")
	}
}

// TestSwapRefusal_ReleaseSignPassesWhenSwapOff verifies the inverse:
// the binary signs normally when /proc/swaps shows no active swap.
// Confirms the swap check is precisely scoped — it doesn't break the
// happy path on swap-off runners.
func TestSwapRefusal_ReleaseSignPassesWhenSwapOff(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: swapEnv(t, key, false),
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")

	if code != 0 {
		t.Fatalf("expected exit 0 with swap off, got %d\nstderr: %s", code, stderr)
	}

	if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("signature should have been created on swap-off host")
	}
}

// TestSwapRefusal_DebugFlagOnASwapFreeHostDoesNotWarn pins the other half of
// the override's contract: --debug-allow-swap waives an ACTIVE swap area, so on
// a host with no swap it waives nothing and must stay quiet.
//
// The warning it would otherwise emit says "DO NOT USE FOR PRODUCTION
// RELEASES". Emitting that when the policy was satisfied on its own terms is
// how a loud warning becomes background noise — and this flag's whole value is
// that seeing it means something.
func TestSwapRefusal_DebugFlagOnASwapFreeHostDoesNotWarn(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := swapEnv(t, key, false) // swap OFF
	env["GITHUB_ACTIONS"] = "true"
	env["CI"] = "true"

	_, stderr, code := run(t, runOpts{dir: dir, env: env},
		"release", "sign", "--debug-allow-swap", "--release-artifacts-dir", "release-artifacts")
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}

	if strings.Contains(stderr, "::warning::") {
		t.Errorf("--debug-allow-swap warned on a swap-free host, where it waived nothing:\n%s", stderr)
	}

	if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Error("signature should still have been produced")
	}
}

// TestSwapRefusal_DebugFlagAllowsSigning verifies the documented
// debug escape hatch through the real CLI: passing --debug-allow-swap
// alongside a swap-on /proc/swaps allows signing to complete and
// the operator gets a Warning annotation in CI logs.
func TestSwapRefusal_DebugFlagAllowsSigning(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := swapEnv(t, key, true)
	// Force the GHA output channel so the test can pin the `::warning::`
	// workflow command. Production runs in GHA always have these set; in
	// unit-test environments they don't, and the annotator falls back to
	// "Warning:" text.
	env["GITHUB_ACTIONS"] = "true"
	env["CI"] = "true"

	_, stderr, code := run(t, runOpts{dir: dir, env: env},
		"release", "sign", "--debug-allow-swap", "--release-artifacts-dir", "release-artifacts")

	if code != 0 {
		t.Fatalf("expected exit 0 with --debug-allow-swap set, got %d\nstderr: %s", code, stderr)
	}

	if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("expected signature when debug override active; not produced")
	}

	assertContains(t, "debug override warning annotation", stderr, "::warning::")

	for _, want := range []string{"--debug-allow-swap", "swap"} {
		assertContains(t, "debug override warning", stderr, want)
	}
}

// TestSwapRefusal_UnreadableSwapStateSoftPasses pins the third branch of the
// policy, which neither test above reaches: when swap state cannot be read at
// all, signing proceeds.
//
// That is deliberate, not an oversight — safeexec.RequireNoSwap documents it:
// refusing without positive evidence of swap would block legitimate
// restricted-container and non-Linux deployments, and the swap check is
// defence-in-depth behind mlock + RLIMIT_CORE + PR_SET_DUMPABLE. But it is the
// branch where a security control yields, so it is worth a test in both
// directions: a regression that flipped it closed would break those
// deployments, and one that made the swap-ON path soft-pass would disable the
// policy silently.
// A missing file represents a non-Linux or /proc-less runner.
func TestSwapRefusal_UnreadableSwapStateSoftPasses(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")

	for _, tc := range []struct {
		name  string
		swaps func(t *testing.T) string
	}{
		{"no such file", func(t *testing.T) string {
			t.Helper()

			return filepath.Join(t.TempDir(), "absent")
		}},
		// A directory, not a mode-0000 file: root reads a 0000 file anyway,
		// and the swap-on body it held then made this row refuse signing on a
		// root runner instead of proving the soft-pass. Nobody can read a
		// directory as a file.
		{"unreadable path", func(t *testing.T) string {
			t.Helper()

			path := filepath.Join(t.TempDir(), "swaps")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}

			return path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := bootstrapGPGKey(t)

			dir := t.TempDir()

			ra := filepath.Join(dir, "release-artifacts")
			if err := os.MkdirAll(ra, 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
				t.Fatal(err)
			}

			env := key.signingEnv(t)
			env["FORGE_CI_PROC_SWAPS"] = tc.swaps(t)

			_, stderr, code := run(t, runOpts{dir: dir, env: env},
				"release", "sign", "--release-artifacts-dir", "release-artifacts")
			if code != 0 {
				t.Fatalf("indeterminate swap state refused signing: exit %d\nstderr: %s", code, stderr)
			}

			if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
				t.Error("signature should have been produced when swap state is indeterminate")
			}

			// The skip is announced. It is a Notice, not a Warning: on a
			// restricted container or a non-Linux runner the indeterminacy is
			// structural and there is nothing for the operator to fix — but
			// the policy did not run, and they did not choose that, so the
			// log has to say so.
			assertContains(t, tc.name, stderr, "swap state could not be determined")
			assertContains(t, tc.name, stderr, "the swap policy did not run")

			if strings.Contains(stderr, "::warning::") {
				t.Errorf("the indeterminate soft-pass must be a Notice, not a Warning — "+
					"it is not a misconfiguration:\n%s", stderr)
			}
		})
	}
}
