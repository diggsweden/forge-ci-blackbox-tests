// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `forge-ci docs` prints the documentation built into the binary, so a user
// reads the pages of the release they run, offline.
package blackbox

import (
	"strings"
	"testing"
)

// TestDocs_ListsAndPrintsShippedPages: the list names the pages, a page comes
// back as Markdown, and a unique prefix is enough to find it.
func TestDocs_ListsAndPrintsShippedPages(t *testing.T) {
	t.Parallel()

	list, stderr, code := run(t, runOpts{dir: t.TempDir()}, "docs")
	if code != 0 {
		t.Fatalf("docs: exit %d: %s", code, stderr)
	}

	assertContains(t, "page list", list, "artifacts-reference")

	page, stderr, code := run(t, runOpts{dir: t.TempDir()}, "docs", "artifacts-reference")
	if code != 0 {
		t.Fatalf("docs artifacts-reference: exit %d: %s", code, stderr)
	}

	if !strings.HasPrefix(strings.TrimSpace(page), "#") {
		t.Fatalf("the page is not Markdown with a heading first:\n%.200s", page)
	}

	// "artifacts" names one page today; a second artifacts-* page makes the
	// prefix ambiguous and this call the one to change.
	byPrefix, stderr, code := run(t, runOpts{dir: t.TempDir()}, "docs", "artifacts")
	if code != 0 {
		t.Fatalf("docs artifacts: exit %d: %s", code, stderr)
	}

	if byPrefix != page {
		t.Fatal("a unique prefix printed a different page than the full name")
	}
}

// TestDocs_UnknownPageIsUsageError: a page the binary does not carry is the
// caller's mistake, and the error says how to list the ones it has.
func TestDocs_UnknownPageIsUsageError(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "docs", "no-such-page")
	if code != exitUsage {
		t.Fatalf("docs no-such-page: exit %d, want %d: %s", code, exitUsage, stderr)
	}

	assertContains(t, "names the list command", stderr, "run forge-ci docs to list them")
}
