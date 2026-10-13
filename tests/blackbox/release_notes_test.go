// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `release notes` turns the rendered changelog snippet into the release-notes
// file the forge release is created from, with a fallback header when there
// is no snippet and an empty file when there is no version either.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseNotes_FromChangelog verifies that `release notes` reads
// a real git-cliff-style changelog snippet and writes it to the
// target file.
func TestReleaseNotes_FromChangelog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	src := filepath.Join(dir, "ReleasenotesTmp")
	if err := os.WriteFile(src, []byte("## v1.2.3\n\n- feat: nice thing\n- fix: tiny bug\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tgt := filepath.Join(dir, "release-notes.md")

	_, _, code := run(t, runOpts{dir: dir},
		"release", "notes",
		"--source-file", "ReleasenotesTmp",
		"--target-file", "release-notes.md",
		"--release-version", "v1.2.3",
		"--release-commit", "deadbeef")
	if code != 0 {
		t.Fatalf("release notes exit %d", code)
	}

	if !fileExists(tgt) {
		t.Fatalf("release notes target file missing: %s", tgt)
	}

	assertContains(t, "release-notes.md", readFile(t, tgt), "feat: nice thing")
}

// TestReleaseNotes_FallbackOnMissingChangelog verifies the
// fallback-stub behaviour: when the source changelog is absent,
// `release notes` still produces a target file with a header derived
// from --release-version, rather than failing.
func TestReleaseNotes_FallbackOnMissingChangelog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	tgt := filepath.Join(dir, "release-notes.md")

	// The fallback must replace an existing target, not append to it.
	if err := os.WriteFile(tgt, []byte("## v1.1.1 previous release\n\n- stale entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{dir: dir},
		"release", "notes",
		"--source-file", "no-such-file",
		"--target-file", "release-notes.md",
		"--release-version", "v9.9.9",
		"--release-commit", "abc1234")
	if code != 0 {
		t.Fatalf("release notes exit %d", code)
	}

	body := readFile(t, tgt)
	assertContains(t, "fallback", body, "v9.9.9")

	for _, stale := range []string{"v1.1.1", "stale entry"} {
		if strings.Contains(body, stale) {
			t.Errorf("release notes kept the previous run's content (%q); the target must be replaced:\n%s", stale, body)
		}
	}
}

// TestReleaseNotes_WithoutAVersionEmptiesTheTarget pins the third branch of
// `release notes`: with no source changelog AND no --release-version, it
// reports "No release notes generated" and creates the target EMPTY.
// release-create-github.yml can reach this branch because it passes
// RELEASE_VERSION from inputs['release-name'], so an empty release-name lands
// here.
func TestReleaseNotes_WithoutAVersionEmptiesTheTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tgt := filepath.Join(dir, "release-notes.md")

	if err := os.WriteFile(tgt, []byte("## v1.1.1 previous release\n\n- stale entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: dir},
		"release", "notes",
		"--source-file", "no-such-file",
		"--target-file", "release-notes.md")
	if code != 0 {
		t.Fatalf("release notes exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "no-version branch", stderr, "No release notes generated")

	if body := readFile(t, tgt); body != "" {
		t.Errorf("the target still holds a previous run's notes; \"No release notes generated\" "+
			"and the file on disk must agree:\n%s", body)
	}

	// The create-if-missing half of the same branch.
	fresh := t.TempDir()

	if _, _, code = run(t, runOpts{dir: fresh},
		"release", "notes",
		"--source-file", "no-such-file",
		"--target-file", "release-notes.md"); code != 0 {
		t.Fatalf("release notes (fresh dir) exit %d", code)
	}

	if !fileExists(filepath.Join(fresh, "release-notes.md")) {
		t.Error("the branch did not create a missing target")
	}
}
