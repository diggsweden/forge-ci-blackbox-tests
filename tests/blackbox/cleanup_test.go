// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeBuildah is the container runtime clean-cache.sh calls. It records its
// environment and fails with 42 while a fail file is in its directory.
func fakeBuildah(dir string, _ []string) int {
	if err := recordEnv(dir); err != nil {
		return fakeFailed("%v", err)
	}
	if fileExists(filepath.Join(dir, "fail")) {
		return 42
	}

	return 0
}

// TestCleanCache_RemovesOnlyTheSuiteCaches drives scripts/clean-cache.sh
// against a disposable cache root. HOME and TMPDIR both point at it, so the
// script and cacheRoot derive the same root. A canary outside the caches,
// reachable through a link inside them, must survive every row, and every
// row but the held lock must leave no lock behind.
func TestCleanCache_RemovesOnlyTheSuiteCaches(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		// linkedBase reaches the base through a symlink, as macOS reaches
		// /var through /private/var.
		linkedBase, lockHeld, failBuild bool
		// prepare changes the cache layout before the script runs.
		prepare    func(t *testing.T, buildah, outside string)
		want       int
		wantOutput string
	}{
		{name: "removes only the suite caches"},
		{name: "removes through a linked base", linkedBase: true},
		{name: "refuses arguments", args: []string{"--all"}, want: 2},
		{name: "refuses while the lock is held", lockHeld: true, want: 2},
		{name: "refuses a linked cache", want: 2, wantOutput: "linked cache directory", prepare: func(t *testing.T, buildah, outside string) {
			t.Helper()
			if err := os.RemoveAll(buildah); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, buildah); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "refuses a linked runroot", want: 2, wantOutput: "linked cache directory", prepare: func(t *testing.T, buildah, outside string) {
			t.Helper()
			if err := os.Symlink(outside, filepath.Join(buildah, "run")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "refuses a shared cache", want: 2, wantOutput: "group- or world-writable", prepare: func(t *testing.T, buildah, _ string) {
			t.Helper()
			if err := os.Chmod(buildah, 0o777); err != nil { //nolint:gosec // the shared directory the script must refuse.
				t.Fatal(err)
			}
		}},
		{name: "surfaces a buildah failure", failBuild: true, want: 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			if tc.linkedBase {
				link := filepath.Join(t.TempDir(), "base")
				if err := os.Symlink(base, link); err != nil {
					t.Fatal(err)
				}
				base = link
			}
			t.Setenv("HOME", base)
			t.Setenv("TMPDIR", base)
			root, rootErr := cacheRoot()
			if rootErr != nil {
				t.Fatal(rootErr)
			}
			home := filepath.Join(root, "forge-ci-blackbox-home")
			buildah := filepath.Join(root, "forge-ci-blackbox-buildah")
			outside := t.TempDir()
			seedCleanupCaches(t, home, buildah, outside)
			if tc.prepare != nil {
				tc.prepare(t, buildah, outside)
			}
			fakes := installFakeTools(t, "buildah")
			if tc.failBuild {
				if err := os.WriteFile(filepath.Join(fakes, "fail"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			lock := filepath.Join(root, "forge-ci-blackbox.lock")
			if tc.lockHeld {
				release, err := acquireSuiteCacheLock(root)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = release() })
			}

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", append([]string{filepath.Join(suiteDir, "scripts", "clean-cache.sh")}, tc.args...)...) //nolint:gosec // the repository's script and the row's literal arguments.
			// PROBE_CANARY must not reach buildah, which runs in a closed environment.
			cmd.Env = []string{"PATH=" + fakes + ":/usr/bin:/bin", "HOME=" + base, "TMPDIR=" + base, "PROBE_CANARY=private"}
			cmd.WaitDelay = time.Second
			output, runErr := cmd.CombinedOutput()
			var exit *exec.ExitError
			if runErr != nil && !errors.As(runErr, &exit) {
				t.Fatal(runErr)
			}
			if code := cmd.ProcessState.ExitCode(); code != tc.want || !strings.Contains(string(output), tc.wantOutput) {
				t.Fatalf("clean-cache.sh exit %d, want %d and output containing %q:\n%s", code, tc.want, tc.wantOutput, output)
			}

			if body, err := os.ReadFile(filepath.Join(outside, "canary")); err != nil || string(body) != "keep" {
				t.Errorf("cleanup reached outside the caches: %q, %v", body, err)
			}
			if _, err := os.Lstat(lock); errors.Is(err, os.ErrNotExist) == tc.lockHeld {
				t.Errorf("lock left=%v, want %v", !errors.Is(err, os.ErrNotExist), tc.lockHeld)
			}
			removed := tc.want == 0
			for _, cache := range []string{home, buildah} {
				if _, err := os.Lstat(cache); errors.Is(err, os.ErrNotExist) != removed {
					t.Errorf("%s removed=%v, want %v", cache, errors.Is(err, os.ErrNotExist), removed)
				}
			}

			store := "buildah --root " + filepath.Join(buildah, "storage") + " --runroot " + filepath.Join(buildah, "run")
			wantCalls := ""
			switch {
			case removed:
				wantCalls = store + " rm --all\n" + store + " rmi --all\n"
			case tc.failBuild:
				wantCalls = store + " rm --all\n"
			}
			if got := fakeCalls(t, fakes); got != wantCalls {
				t.Errorf("buildah calls:\n%s\nwant:\n%s", got, wantCalls)
			}
			if wantCalls == "" {
				return
			}
			env := fakeEnv(t, fakes)
			slices.Sort(env)
			if len(env) != 2 || env[0] != "HOME="+home || !strings.HasPrefix(env[1], "PATH=") {
				t.Errorf("buildah environment is not just PATH and the suite home: %q", env)
			}
		})
	}
}

// Seed realistic cache contents, including a read-only Go module and a link
// to an outside canary that cleanup must never follow.
func seedCleanupCaches(t *testing.T, home, buildah, outside string) {
	t.Helper()

	module := filepath.Join(home, "go", "pkg", "mod", "fixture")
	for _, dir := range []string{module, filepath.Join(buildah, "storage")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(module, "source.go"), filepath.Join(home, "canary"), filepath.Join(outside, "canary")} {
		if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(module, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(module, 0o700) })

	if err := os.Symlink(outside, filepath.Join(home, "external")); err != nil {
		t.Fatal(err)
	}
}
