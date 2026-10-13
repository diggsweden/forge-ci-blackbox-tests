// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `platform checkout` and `platform resolve-ref`
// — the foundational verbs every pipeline starts with (clone the repo at
// a ref; resolve a ref to a SHA). Both are driven against a LOCAL bare
// repo standing in for the forge: the checkout remote is built as
// `<server-url>/<repository>.git`, and git accepts a filesystem path as a
// remote, so no network is involved. This also exercises the sha256
// object-format path, where go-git can't open the repo and the SHA has to
// come from the `git rev-parse` subprocess fallback.

package blackbox

import (
	"net/http/cgi" //nolint:gosec // G504 is the Httpoxy blocklist for Go < 1.6.3; this serves a test fixture over loopback.
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// gitAt runs git in dir, fails the test on error, and returns trimmed
// stdout. isolatedEnv already supplies the host-isolated config stack and
// the test identity, so `commit` works during fixture seeding.
func gitAt(t *testing.T, dir string, args ...string) string {
	t.Helper()

	return outputOrFatal(t, toolCommand(t, dir, nil, "git", args...))
}

// seedForgeRepo builds a local stand-in forge: a bare repo at
// <root>/org/app.git seeded with one commit on main plus a lightweight tag
// v1.0.0, served over loopback smart HTTP. objectFormat "" uses git's default
// (sha1). Returns the server base URL (for checkout's --server-url), the bare
// repo path (for resolve-ref's --remote-url, since ls-remote reads a path
// directly), and the HEAD SHA.
//
// The server is real git: `git http-backend` behind an httptest server, the
// same shape the engine's own fake git server uses. checkout refuses anything
// but an HTTP(S) base URL for --server-url, because that string becomes the
// remote a credential header is sent to, so a filesystem path cannot stand in
// for the forge here.
func seedForgeRepo(t *testing.T, objectFormat string) (srv, bareDir, headSHA string) {
	t.Helper()
	requireTool(t, "git")

	root := t.TempDir()
	bareDir = filepath.Join(root, "org", "app.git")
	srv = serveGitHTTP(t, root)

	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}

	fmtArg := []string{}
	if objectFormat != "" {
		fmtArg = []string{"--object-format=" + objectFormat}
	}

	gitAt(t, root, append(append([]string{"init", "--bare", "-q"}, fmtArg...), bareDir)...)

	work := t.TempDir()
	gitAt(t, work, append([]string{"init", "-q", "-b", "main"}, fmtArg...)...)

	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gitAt(t, work, "add", "README.md")
	gitAt(t, work, "commit", "-q", "-m", "c0")
	gitAt(t, work, "tag", "v1.0.0")
	gitAt(t, work, "remote", "add", "origin", bareDir)
	gitAt(t, work, "push", "-q", "origin", "main", "v1.0.0")

	return srv, bareDir, gitAt(t, work, "rev-parse", "HEAD")
}

// serveGitHTTP serves every bare repository under root over the smart HTTP
// protocol on a loopback port and returns the base URL. Reads are anonymous
// (GIT_HTTP_EXPORT_ALL); nothing is writable, which is all a checkout needs.
func serveGitHTTP(t *testing.T, root string) string {
	t.Helper()

	handler := &cgi.Handler{
		Path: lookupTool("git"),
		Args: []string{"http-backend"},
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server.URL
}

// requireGitSHA256 skips only in the optional profile when the host git cannot
// create SHA-256 repositories. Strict evidence requires this path.
func requireGitSHA256(t *testing.T) {
	t.Helper()
	requireTool(t, "git")

	cmd := toolCommand(t, "", nil, "git", "init", "-q", "--object-format=sha256", filepath.Join(t.TempDir(), "probe"))

	if out, err := cmd.CombinedOutput(); err != nil {
		skipInOptionalProfilef(t, "git lacks sha256 object-format support: %v\n%s", err, out)
	}
}

// ghaOutputFile returns a pre-created empty file to hand the CLI as
// $GITHUB_OUTPUT so its output sink has somewhere to append.
func ghaOutputFile(t *testing.T) string {
	t.Helper()

	f := filepath.Join(t.TempDir(), "gh-output")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	return f
}

// TestPlatformCheckout_TagCheckoutSHA1 clones a tag out of the local
// forge and asserts the working tree, the resolved SHA on the output
// sink, and the human status line.
func TestPlatformCheckout_TagCheckoutSHA1(t *testing.T) {
	t.Parallel()

	srv, _, headSHA := seedForgeRepo(t, "")

	dest := t.TempDir() // must be empty — checkout refuses a pre-existing .git
	outFile := ghaOutputFile(t)

	_, stderr, code := run(t, runOpts{
		dir: t.TempDir(),
		env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": outFile},
	},
		"platform", "checkout",
		"--repository", "org/app",
		"--server-url", srv, // remote resolves to <srv>/org/app.git over smart HTTP
		"--ref", "v1.0.0",
		"--workspace", dest,
		"--object-format", "sha1", // set explicitly to skip the forge-metadata network probe
	)

	if code != 0 {
		t.Fatalf("checkout exit %d\nstderr: %s", code, stderr)
	}

	if fi, err := os.Stat(filepath.Join(dest, ".git")); err != nil || !fi.IsDir() {
		t.Fatalf("workspace has no .git after checkout")
	}

	if got := gitAt(t, dest, "rev-parse", "HEAD"); got != headSHA {
		t.Errorf("checked-out HEAD %s, want %s", got, headSHA)
	}

	if !fileExists(filepath.Join(dest, "README.md")) {
		t.Errorf("tracked file README.md not present in the checkout")
	}

	if outs := parseGHAOutputs(t, outFile); outs["checkout-sha"] != headSHA {
		t.Errorf("output checkout-sha=%q, want %s", outs["checkout-sha"], headSHA)
	}

	assertContains(t, "stderr", stderr, "Checked out org/app at "+headSHA+" (sha1)")
}

// TestPlatformCheckout_Sha256 exercises the sha256 object-format path:
// go-git can't open a sha256 repo, so the 64-char SHA has to come from
// the `git rev-parse` subprocess fallback. Asserts the working tree is a
// real sha256 repo and the resolved 64-char digest reaches the sink.
func TestPlatformCheckout_Sha256(t *testing.T) {
	t.Parallel()

	requireGitSHA256(t)

	srv, _, headSHA := seedForgeRepo(t, "sha256")
	if len(headSHA) != 64 {
		t.Fatalf("expected a 64-char sha256 HEAD, got %q", headSHA)
	}

	dest := t.TempDir()
	outFile := ghaOutputFile(t)

	_, stderr, code := run(t, runOpts{
		dir: t.TempDir(),
		env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": outFile},
	},
		"platform", "checkout",
		"--repository", "org/app",
		"--server-url", srv,
		"--ref", "v1.0.0",
		"--workspace", dest,
		"--object-format", "sha256",
	)

	if code != 0 {
		t.Fatalf("sha256 checkout exit %d\nstderr: %s", code, stderr)
	}

	if got := gitAt(t, dest, "rev-parse", "HEAD"); got != headSHA {
		t.Errorf("checked-out HEAD %s, want %s", got, headSHA)
	}

	if of := gitAt(t, dest, "rev-parse", "--show-object-format"); of != "sha256" {
		t.Errorf("checkout object-format %q, want sha256", of)
	}

	if outs := parseGHAOutputs(t, outFile); outs["checkout-sha"] != headSHA {
		t.Errorf("output checkout-sha=%q, want the 64-char %s", outs["checkout-sha"], headSHA)
	}

	assertContains(t, "stderr", stderr, "(sha256)")
}

// TestPlatformCheckout_RejectsBadInput pins the exit-code contract:
// missing required inputs are EX_USAGE (2); a present-but-rejected input
// (bad ref, dirty workspace) is EX_VALIDATION (1).
func TestPlatformCheckout_RejectsBadInput(t *testing.T) {
	t.Parallel()

	srv, _, _ := seedForgeRepo(t, "")

	// Each refusal pins the sentence naming its own rule: two rules share
	// EX_USAGE and two share EX_VALIDATION, so a code-only check lets a row
	// pass on a neighbour's failure.
	t.Run("missing_repository_is_usage", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "checkout",
			"--server-url", srv, "--ref", "v1.0.0",
			"--workspace", t.TempDir(), "--object-format", "sha1")
		if code != exitUsage {
			t.Errorf("missing --repository: exit %d, want 2 (EX_USAGE)", code)
		}

		assertContains(t, "missing repository", stderr, "repository (owner/name) is required")
	})

	t.Run("missing_ref_is_usage", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "checkout",
			"--repository", "org/app", "--server-url", srv,
			"--workspace", t.TempDir(), "--object-format", "sha1")
		if code != exitUsage {
			t.Errorf("missing --ref: exit %d, want 2 (EX_USAGE)", code)
		}

		assertContains(t, "missing ref", stderr, "ref is required")
	})

	t.Run("nonexistent_ref_is_validation", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "checkout",
			"--repository", "org/app", "--server-url", srv,
			"--ref", "v9.9.9-does-not-exist",
			"--workspace", t.TempDir(), "--object-format", "sha1")
		if code != exitValidation {
			t.Errorf("nonexistent ref: exit %d, want 1 (EX_VALIDATION)", code)
		}

		assertContains(t, "nonexistent ref", stderr, `ref "v9.9.9-does-not-exist" not found as a tag or branch`)
	})

	// Renamed from "nonempty_workspace_is_validation", which overstated the
	// guard: the refusal is specifically about an existing .git, not about the
	// workspace being non-empty. The next case pins that boundary.
	t.Run("existing_git_dir_is_validation", func(t *testing.T) {
		dirty := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dirty, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}

		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "checkout",
			"--repository", "org/app", "--server-url", srv, "--ref", "v1.0.0",
			"--workspace", dirty, "--object-format", "sha1")
		if code != exitValidation {
			t.Errorf("workspace with existing .git: exit %d, want 1 (EX_VALIDATION)", code)
		}

		assertContains(t, "existing .git", stderr, "already contains a .git")
	})

	// The other side of that boundary, probed and pinned: a workspace holding
	// unrelated files but no .git is ACCEPTED, and those files survive the
	// checkout. CI workspaces routinely carry restored caches, so refusing
	// them would be a real regression — and reading the guard as "the
	// workspace must be empty" is the mistake the old subtest name invited.
	t.Run("nonempty_workspace_without_git_is_accepted", func(t *testing.T) {
		dest := t.TempDir()

		stray := filepath.Join(dest, "restored-cache.txt")
		if err := os.WriteFile(stray, []byte("cache"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "checkout",
			"--repository", "org/app", "--server-url", srv, "--ref", "v1.0.0",
			"--workspace", dest, "--object-format", "sha1")
		if code != 0 {
			t.Fatalf("a workspace with unrelated files was refused: exit %d\nstderr: %s", code, stderr)
		}

		if !fileExists(stray) {
			t.Error("checkout removed an unrelated pre-existing file from the workspace")
		}

		if fi, err := os.Stat(filepath.Join(dest, ".git")); err != nil || !fi.IsDir() {
			t.Error("checkout did not produce a .git in the workspace")
		}
	})
}

// TestPlatformResolveRef_ResolvesTag resolves a tag to its SHA via
// `git ls-remote` against the local bare repo — no checkout, no network.
func TestPlatformResolveRef_ResolvesTag(t *testing.T) {
	t.Parallel()

	_, bareDir, headSHA := seedForgeRepo(t, "")

	outFile := ghaOutputFile(t)

	_, stderr, code := run(t, runOpts{
		dir: t.TempDir(),
		env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": outFile},
	},
		"platform", "resolve-ref",
		"--remote-url", bareDir, // local bare path; ls-remote reads it directly
		"--ref", "v1.0.0",
	)

	if code != 0 {
		t.Fatalf("resolve-ref exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "stderr", stderr, headSHA)

	if outs := parseGHAOutputs(t, outFile); outs["sha"] != headSHA {
		t.Errorf("output sha=%q, want %s", outs["sha"], headSHA)
	}
}

// TestPlatformResolveRef_RejectsBadInput pins the two distinctive
// failure codes: a ref that ls-remote can't find (but the remote is
// reachable) is EX_CONFIG (78); a missing --ref is EX_USAGE (2).
func TestPlatformResolveRef_RejectsBadInput(t *testing.T) {
	t.Parallel()

	_, bareDir, _ := seedForgeRepo(t, "")

	t.Run("absent_ref_is_config_error", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "resolve-ref", "--remote-url", bareDir, "--ref", "does-not-exist")
		if code != exitConfig {
			t.Errorf("absent ref: exit %d, want 78 (EX_CONFIG)", code)
		}

		assertContains(t, "absent ref", stderr, `ref "does-not-exist" was not found`)
	})

	t.Run("missing_ref_is_usage", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"platform", "resolve-ref", "--remote-url", bareDir)
		if code != exitUsage {
			t.Errorf("missing --ref: exit %d, want 2 (EX_USAGE)", code)
		}

		assertContains(t, "missing ref", stderr, "ref is required")
	})
}
