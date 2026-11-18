// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestChangelogValidate_RequiredChecksPresenceNotContent pins what this verb
// actually does, which is narrower than "validate" suggests: with --required it
// checks the file EXISTS and reports its line count. It does not inspect the
// content at all.
// The table makes that boundary explicit with well-formed, empty, and arbitrary
// content.
func TestChangelogValidate_RequiredChecksPresenceNotContent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
	}{
		{"well_formed", "# Changelog\n\n## v1.0.0\n\n- initial release\n"},
		{"empty_file", ""},
		{"not_a_changelog", "not a changelog at all\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, code := run(t, runOpts{dir: dir},
				"validate", "changelog", "--path", "CHANGELOG.md", "--required")
			if code != 0 {
				t.Fatalf("validate changelog exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}

			// The success line is the discriminator: exit 0 alone is also what
			// the no---required minimal mode returns for a file that is not
			// there at all.
			assertContains(t, tc.name, stdout+stderr, "Full changelog found")
		})
	}
}

// TestChangelogValidate_RequiredMissingIsNoInput verifies that --required +
// missing file → EX_NOINPUT (66), and that the message names the path.
func TestChangelogValidate_RequiredMissingIsNoInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, stderr, code := run(t, runOpts{dir: dir},
		"validate", "changelog", "--path", "DOES-NOT-EXIST.md", "--required")
	if code != exitNoInput {
		t.Errorf("expected EX_NOINPUT=66 when --required and file missing; got %d", code)
	}

	assertContains(t, "missing changelog", stderr, "DOES-NOT-EXIST.md")
}

// TestChangelogValidate_MinimalModeToleratesAbsent verifies that without
// --required, an absent changelog is tolerated (used by the minimal
// changelog mode in the workflow, which has a "No changes for this
// release" fallback).
func TestChangelogValidate_MinimalModeToleratesAbsent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, _, code := run(t, runOpts{dir: dir, env: map[string]string{
		// validate changelog emits via the OutputSink; without
		// GITHUB_OUTPUT it writes to stdout-as-text which is fine.
	}}, "validate", "changelog", "--path", "DOES-NOT-EXIST.md")
	if code != 0 {
		t.Errorf("expected exit 0 in minimal mode with missing file; got %d", code)
	}
}
