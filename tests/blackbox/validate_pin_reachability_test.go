// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `validate pin-reachability`. Workflows pin the
// forge-ci provider by full commit SHA; a history rewrite can leave
// a pin pointing at an orphaned commit that object GC will eventually
// drop, turning it into a confusing runtime failure. This validator
// catches that early. Driven hermetically against a local git repo via
// --repo-dir, so no clone or network happens; the "forge" is just a
// throwaway repo with a reachable commit and an orphaned one.

package blackbox

import (
	"fmt"
	"testing"
)

// pinnedWorkflow writes a workflow whose sign job pins forgejo-ci at sha,
// matching the `uses: fixture/forgejo-ci/....yml@<sha>` shape the
// reachability scanner looks for. Returns the workflow path.
func pinnedWorkflow(t *testing.T, sha string) string {
	t.Helper()

	return writeTempWorkflow(t, fmt.Sprintf(`jobs:
  sign:
    uses: fixture/forgejo-ci/.forgejo/workflows/sign.yml@%s
`, sha))
}

// seedPinRepo builds a throwaway repo on main and returns its dir plus a
// reachable SHA (on main) and an orphaned SHA (committed then reset away,
// so it resolves but is unreachable from main and has no tag).
func seedPinRepo(t *testing.T, objectFormat string) (repo, reachable, orphan string) {
	t.Helper()
	requireTool(t, "git")

	repo = t.TempDir()
	gitAt(t, repo, "init", "-q", "-b", "main", "--object-format="+objectFormat)
	gitAt(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	reachable = gitAt(t, repo, "rev-parse", "HEAD")
	gitAt(t, repo, "commit", "-q", "--allow-empty", "-m", "orphan")
	orphan = gitAt(t, repo, "rev-parse", "HEAD")
	gitAt(t, repo, "reset", "--hard", reachable)

	return repo, reachable, orphan
}

// TestPinReachability_ReachablePasses: a pin to a commit on main passes.
func TestPinReachability_ReachablePasses(t *testing.T) {
	t.Parallel()

	repo, reachable, _ := seedPinRepo(t, "sha1")
	wf := pinnedWorkflow(t, reachable)

	_, stderr, code := run(t, runOpts{},
		"validate", "pin-reachability", "--repo-dir", repo, "--subject", "forgejo-ci", "--main", "main", "--workflow", wf)

	if code != 0 {
		t.Fatalf("expected exit 0 for reachable pin, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "reachable pin", stderr, "All forgejo-ci pins are reachable")
}

// TestPinReachability_OrphanedFails: a pin to a commit no longer reachable
// from main (and pointed to by no tag) is rejected.
func TestPinReachability_OrphanedFails(t *testing.T) {
	t.Parallel()

	repo, _, orphan := seedPinRepo(t, "sha1")
	wf := pinnedWorkflow(t, orphan)

	_, stderr, code := run(t, runOpts{},
		"validate", "pin-reachability", "--repo-dir", repo, "--subject", "forgejo-ci", "--main", "main", "--workflow", wf)

	if code != exitValidation { // EX_VALIDATION: orphaned pin
		t.Fatalf("expected EX_VALIDATION=1 for orphaned pin, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "orphaned pin", stderr, "ORPHANED")
	assertContains(t, "orphaned pin", stderr, "is not reachable from main nor any tag")
}

func TestPinReachability_SHA256(t *testing.T) {
	t.Parallel()
	requireGitSHA256(t)
	repo, reachable, orphan := seedPinRepo(t, "sha256")

	for _, scenario := range []struct {
		name, pin string
		code      int
	}{
		{"reachable", reachable, 0},
		{"orphaned", orphan, exitValidation},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()

			if len(scenario.pin) != 64 {
				t.Fatalf("fixture is not a SHA-256 repository: %q", scenario.pin)
			}

			_, stderr, code := run(t, runOpts{}, "validate", "pin-reachability",
				"--repo-dir", repo, "--subject", "fixture/forgejo-ci", "--main", "main",
				"--workflow", pinnedWorkflow(t, scenario.pin))
			if code != scenario.code {
				t.Fatalf("SHA-256 pin check: exit %d, want %d: %s", code, scenario.code, stderr)
			}
		})
	}
}
