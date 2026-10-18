// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestContainerLedger_AddAndValidate covers the registry-free half of the
// build-once/promote-many image ledger: `container ledger add` (record an
// image entry) and `container ledger validate` (re-check the recorded
// entries against the release tag at the trust boundary). These are pure,
// offline operations — the promote / verify / cleanup verbs that touch a
// real registry via cosign are not exercised here (same boundary docs/scope.md
// draws for container signing).
//
// Covered: an entry is appended as a JSON array; `add` is idempotent on
// retry; `validate` accepts the matching release tag and rejects a tag the
// final_tag is not scoped to; a malformed digest is rejected at add time.
func TestContainerLedger_AddAndValidate(t *testing.T) {
	t.Parallel()

	dig := "sha256:" + strings.Repeat("a", 64)
	ledger := filepath.Join(t.TempDir(), "dist", "release-images.json")

	add := func() (stderr string, code int) {
		_, stderr, code = run(t, runOpts{},
			"container", "ledger", "add",
			"--ledger", ledger,
			"--tag", "v1.2.3",
			"--role", "distroless",
			"--ref", "ghcr.io/diggsweden/demo@"+dig,
			"--digest", dig,
			"--final-tag", "ghcr.io/diggsweden/demo:v1.2.3",
			"--sbom", "dist/image-sbom-amd64.cyclonedx.json",
		)

		return stderr, code
	}

	// First add creates the ledger file (and its dir) and appends the entry.
	stderr, code := add()
	if code != 0 {
		t.Fatalf("ledger add exit=%d stderr=%s", code, stderr)
	}

	assertContains(t, "ledger add", stderr, "appended")

	entries := readLedger(t, ledger)
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}

	if entries[0]["digest"] != dig || entries[0]["final_tag"] != "ghcr.io/diggsweden/demo:v1.2.3" {
		t.Errorf("recorded entry = %+v", entries[0])
	}

	// A retried build job re-adds the same entry: idempotent, no growth.
	stderr, code = add()
	if code != 0 {
		t.Fatalf("idempotent re-add exit=%d stderr=%s", code, stderr)
	}

	assertContains(t, "ledger re-add", stderr, "already recorded")

	if got := len(readLedger(t, ledger)); got != 1 {
		t.Errorf("idempotent re-add grew ledger to %d entries", got)
	}

	// validate accepts the entry for the matching release tag.
	if _, stderr, code = run(t, runOpts{},
		"container", "ledger", "validate", "--ledger", ledger, "--tag", "v1.2.3"); code != 0 {
		t.Fatalf("ledger validate (matching tag) exit=%d stderr=%s", code, stderr)
	}

	// ...and rejects it (EX_VALIDATION) when final_tag is not scoped to the tag.
	// The message is pinned, not just the code: every rule in ValidateAll exits
	// 1, so a bare code check cannot tell the scoping rule from any other one.
	// Mutation-verified — with the code-only check, making the scoping rule
	// report an unrelated failure left this test green.
	_, stderr, code = run(t, runOpts{},
		"container", "ledger", "validate", "--ledger", ledger, "--tag", "v9.9.9")
	if code != exitValidation {
		t.Errorf("ledger validate (wrong tag) exit=%d, want 1 (EX_VALIDATION)", code)
	}

	assertContains(t, "ledger validate (wrong tag)", stderr,
		`final_tag "ghcr.io/diggsweden/demo:v1.2.3" must be scoped to release tag "v9.9.9"`)

	// A malformed digest is rejected at add time, not silently recorded — and
	// the message names the digest rule, so this cannot pass on some other
	// validation failure (a missing flag, say, would exit 2 anyway).
	_, stderr, code = run(t, runOpts{},
		"container", "ledger", "add",
		"--ledger", filepath.Join(t.TempDir(), "bad.json"),
		"--tag", "v1.2.3",
		"--ref", "ghcr.io/diggsweden/demo@"+dig,
		"--digest", "sha256:short",
		"--final-tag", "ghcr.io/diggsweden/demo:v1.2.3")
	if code != exitValidation {
		t.Errorf("ledger add (bad digest) exit=%d, want 1 (EX_VALIDATION)", code)
	}

	assertContains(t, "ledger add (bad digest)", stderr, `digest must be sha256:<64 hex>: "sha256:short"`)
}

// TestContainerLedger_EmptyLedgerIsRefusedByDefault pins the release gate.
//
// `validate` runs immediately before `promote` in promote-stage.yml, and there
// an empty ledger is never legitimate: it means the build job's `ledger add`
// did not run, or ran against a different --ledger path. Validation refuses by
// default, with --allow-empty for the deliberate case.
func TestContainerLedger_EmptyLedgerIsRefusedByDefault(t *testing.T) {
	t.Parallel()

	ledger := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(ledger, []byte("[]\n"), 0o644); err != nil {
		t.Fatalf("write empty ledger: %v", err)
	}

	_, stderr, code := run(t, runOpts{},
		"container", "ledger", "validate", "--ledger", ledger, "--tag", "v1.2.3")
	if code != exitValidation {
		t.Errorf("validate on an empty ledger exit=%d, want 1 (EX_VALIDATION)", code)
	}

	// The message names the path, so an operator who pointed --ledger at the
	// wrong file can see which file was empty.
	assertContains(t, "validate (empty ledger)", stderr, "contains no entries")
	assertContains(t, "validate (empty ledger)", stderr, ledger)

	// --allow-empty is the deliberate opt-out.
	_, stderr, code = run(t, runOpts{},
		"container", "ledger", "validate", "--ledger", ledger, "--tag", "v1.2.3", "--allow-empty")
	if code != 0 {
		t.Fatalf("validate --allow-empty exit=%d, want 0\nstderr: %s", code, stderr)
	}

	assertContains(t, "validate --allow-empty", stderr, "0 entr(y/ies) valid")
}

// TestContainerLedger_MergeDedupes covers `container ledger merge`, which folds the
// per-container single-entry ledgers a multi-container release produces into
// one ledger that promotes as a single gated unit. Exact duplicates are
// dropped.
func TestContainerLedger_MergeDedupes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	digA := "sha256:" + strings.Repeat("a", 64)
	digB := "sha256:" + strings.Repeat("b", 64)

	seed := func(ledger, role, image, digest string) {
		t.Helper()

		_, stderr, code := run(t, runOpts{},
			"container", "ledger", "add",
			"--ledger", ledger,
			"--tag", "v1.2.3",
			"--role", role,
			"--ref", image+"@"+digest,
			"--digest", digest,
			"--final-tag", image+":v1.2.3",
		)
		if code != 0 {
			t.Fatalf("seed ledger add exit=%d stderr=%s", code, stderr)
		}
	}

	ledgerA := filepath.Join(dir, "a.json")
	ledgerB := filepath.Join(dir, "b.json")
	seed(ledgerA, "api", "ghcr.io/diggsweden/api", digA)
	seed(ledgerB, "worker", "ghcr.io/diggsweden/worker", digB)

	// Two distinct single-entry ledgers merge into one two-entry ledger.
	merged := filepath.Join(dir, "merged.json")
	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "merge", "--ledger", merged, ledgerA, ledgerB); code != 0 {
		t.Fatalf("ledger merge exit=%d stderr=%s", code, stderr)
	}

	// Both digests, not just a count of two: a merge that read one input
	// twice would also produce two entries.
	entries := readLedger(t, merged)
	if got := len(entries); got != 2 {
		t.Fatalf("merged entries = %d, want 2", got)
	}

	found := map[any]bool{}
	for _, entry := range entries {
		found[entry["digest"]] = true
	}

	if !found[digA] || !found[digB] {
		t.Errorf("merged ledger lost an input entry: %+v", entries)
	}

	// Merging a ledger with itself drops the exact duplicate.
	dedup := filepath.Join(dir, "dedup.json")
	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "merge", "--ledger", dedup, ledgerA, ledgerA); code != 0 {
		t.Fatalf("ledger merge (dedup) exit=%d stderr=%s", code, stderr)
	}

	if got := len(readLedger(t, dedup)); got != 1 {
		t.Errorf("self-merge entries = %d, want 1 (exact duplicate dropped)", got)
	}
}

// readLedger parses a ledger file as the bare JSON array of entries the
// `add`/`merge` commands write.
func readLedger(t *testing.T, path string) []map[string]any {
	t.Helper()

	var entries []map[string]any
	decodeJSON(t, "ledger "+path, readFile(t, path), &entries)

	return entries
}
