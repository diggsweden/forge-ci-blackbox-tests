// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the request → promote release flow: a human pushes
// a SIGNED `release-request/vX.Y.Z` tag; forge-ci derives the release
// identity + original-tagger trailers (`version release-context`), and creates
// the final `vX.Y.Z` tag ONCE at the bump commit without force-push or tag
// mutation (`version tag-release`). This drives the CLI commands the
// version-bump workflow chains, and asserts the immutability invariants:
//
//   - the request tag stays put (never moved onto the bump commit),
//   - the final tag is created at the bump commit (HEAD),
//   - a second tag-release refuses (create-once),
//   - the bump-commit trailers record the original tagger.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasePromote_RequestTagBecomesImmutableReleaseTag(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	// A bare remote for tag-release to push the final tag to.
	bare := t.TempDir()
	gitAt(t, bare, "init", "--bare", ".")

	// Build the repo: commit C0 + signed release-request/v1.0.0 at C0, then a
	// bump commit C1 on top (the commit the release tag should land on).
	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		makeGPGSignedTag(t, runGit, repo, key, "release-request/v1.0.0") // commit C0 + signed request tag
		mustGit(t, runGit, "remote", "add", "origin", bare)

		// C1: the bot's version-bump + changelog commit.
		if err := os.WriteFile(filepath.Join(repo, "CHANGELOG.md"), []byte("# v1.0.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "CHANGELOG.md")
		mustGit(t, runGit, "commit", "-q", "-m", "chore(release): v1.0.0")
	})

	c0 := gitAt(t, repo, "rev-list", "-n", "1", "release-request/v1.0.0")
	c1 := gitAt(t, repo, "rev-parse", "HEAD")

	if c0 == c1 {
		t.Fatal("fixture broken: request tag and bump commit must differ")
	}

	// 1) release-context derives the release identity + tagger trailers.
	outFile := filepath.Join(t.TempDir(), "ctx-output")
	_, stderr, code := run(t, runOpts{
		dir: repo,
		env: map[string]string{
			"GITHUB_REF_NAME": "release-request/v1.0.0",
			"GNUPGHOME":       key.gnupgHome,
			"GITHUB_OUTPUT":   outFile,
			"GITHUB_ACTIONS":  "true",
		},
	}, "version", "derive-release")
	if code != 0 {
		t.Fatalf("release-context exit %d\nstderr: %s", code, stderr)
	}

	outputs := parseGHAOutputs(t, outFile)
	if outputs["release-tag"] != "v1.0.0" {
		t.Errorf("release-tag = %q, want v1.0.0", outputs["release-tag"])
	}

	if outputs["version"] != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", outputs["version"])
	}

	trailers := outputs["commit-trailers"]
	if !strings.Contains(trailers, "Release-Request: release-request/v1.0.0") {
		t.Errorf("commit-trailers missing Release-Request:\n%s", trailers)
	}

	// Each original-tagger line must name the tagging key's identity, not just
	// appear.
	for _, prefix := range []string{"Release-Authorized-By:", "Co-authored-by:"} {
		found := false

		for line := range strings.Lines(trailers) {
			if strings.HasPrefix(line, prefix) {
				found = true

				assertContains(t, prefix+" names the tagger", line, "integration@test.example")
			}
		}

		if !found {
			t.Errorf("commit-trailers missing %s line:\n%s", prefix, trailers)
		}
	}

	// 2) tag-release creates v1.0.0 ONCE at HEAD (the bump commit) and pushes it.
	_, stderr, code = run(t, runOpts{
		dir: repo,
		env: map[string]string{"GNUPGHOME": key.gnupgHome, "RELEASE_TAG": "v1.0.0"},
	}, "version", "tag-release")
	if code != 0 {
		t.Fatalf("tag-release exit %d\nstderr: %s", code, stderr)
	}

	// The final tag is at the bump commit…
	if got := gitAt(t, repo, "rev-list", "-n", "1", "v1.0.0"); got != c1 {
		t.Errorf("v1.0.0 points at %s, want bump commit %s", got, c1)
	}

	// …and the request tag is UNTOUCHED (never moved onto the bump commit).
	if got := gitAt(t, repo, "rev-list", "-n", "1", "release-request/v1.0.0"); got != c0 {
		t.Errorf("request tag moved to %s, must stay immutable at %s", got, c0)
	}

	// The final tag was pushed to the remote. (That the push is non-force
	// is argv-level engine behaviour; a fresh remote cannot tell the two
	// apart, so this only pins that the tag arrived.)
	if remote := gitAt(t, bare, "tag", "-l", "v1.0.0"); remote != "v1.0.0" {
		t.Errorf("v1.0.0 not pushed to remote; got %q", remote)
	}

	// 3) Create once: an exact rerun is a no-op, while a rerun from another
	// commit must refuse to move the release tag.
	_, stderr, code = run(t, runOpts{
		dir: repo,
		env: map[string]string{"GNUPGHOME": key.gnupgHome, "RELEASE_TAG": "v1.0.0"},
	}, "version", "tag-release")
	if code != 0 {
		t.Fatalf("an exact rerun must be a tolerated no-op; got exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "exact rerun", stderr, "rerun is a no-op")

	if got := gitAt(t, repo, "rev-list", "-n", "1", "v1.0.0"); got != c1 {
		t.Errorf("the no-op rerun moved v1.0.0 to %s, must stay at %s", got, c1)
	}

	// Once HEAD moves, the rerun must refuse rather than re-point the tag.
	if err := os.WriteFile(filepath.Join(repo, "AFTER.md"), []byte("later work\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gitAt(t, repo, "add", "AFTER.md")
	gitAt(t, repo, "commit", "-q", "-m", "work after the release")

	_, stderr, code = run(t, runOpts{
		dir: repo,
		env: map[string]string{"GNUPGHOME": key.gnupgHome, "RELEASE_TAG": "v1.0.0"},
	}, "version", "tag-release")
	if code == 0 {
		t.Fatalf("tag-release moved the release tag onto a later commit; must refuse\nstderr: %s", stderr)
	}

	assertContains(t, "moved-HEAD refusal", stderr, "refusing to move it")

	// "Refuses" must mean refuses: the tag is still where the first run
	// put it, not moved before the error.
	if got := gitAt(t, repo, "rev-list", "-n", "1", "v1.0.0"); got != c1 {
		t.Errorf("the refused rerun moved v1.0.0 to %s, must stay at %s", got, c1)
	}
}
