// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `release provenance` — generating an
// in-toto/SLSA-v1.0 provenance Statement from a checksums file. Tests
// the statement-only path (no --method/--key, so no signing infra
// needed): the emitted Statement's shape, that subjects mirror the
// checksums, byte-for-byte determinism under a pinned timestamp, and the
// reserved-key collision guard. Build context is supplied entirely via
// provider env, so no git repo is involved.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// provenanceEnv is a fixed GitHub-provider context that makes the
// generated statement fully deterministic.
//
//nolint:gochecknoglobals // read-only fixture context shared by the tests.
var provenanceEnv = map[string]string{
	"FORGE_CI_PROVIDER": "github",
	// The repository URL comes from the runner context, and the GitHub runner
	// context exists only behind its marker; the provider override alone
	// selects the forge API, not the runner.
	"GITHUB_ACTIONS":    "true",
	"GITHUB_SERVER_URL": "https://github.com",
	"GITHUB_REPOSITORY": "fixture/example",
	"GITHUB_REF_NAME":   "v1.2.3",
	"GITHUB_SHA":        strings.Repeat("2", 40), //nolint:mnd // 40-hex commit SHA
	"GITHUB_RUN_ID":     "4242",                  // gives a non-empty builder/invocation id
}

const provStartedOn = "2026-06-01T00:00:00Z"

// writeChecksums drops a two-line GoReleaser-format checksums file in a
// temp dir and returns the dir and the file path.
func writeChecksums(t *testing.T) (dir, path string) {
	t.Helper()

	dir = t.TempDir()
	path = filepath.Join(dir, "checksums.sha256")
	body := strings.Repeat("a", 64) + "  dist/app_linux_amd64.tar.gz\n" +
		strings.Repeat("b", 64) + "  dist/checksums.txt\n"

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write checksums: %v", err)
	}

	return dir, path
}

// provStatement is the subset of the SLSA v1 Statement the tests assert.
type provStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string `json:"name"`
		Digest struct {
			SHA256 string `json:"sha256"`
		} `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			ExternalParameters map[string]any `json:"externalParameters"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Metadata struct {
				StartedOn string `json:"startedOn"`
			} `json:"metadata"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

// TestProvenance_GeneratesStatement checks the statement-only path emits a
// well-formed SLSA v1 Statement whose subjects and context match the
// inputs.
func TestProvenance_GeneratesStatement(t *testing.T) {
	t.Parallel()

	dir, checksums := writeChecksums(t)

	stdout, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv},
		"release", "provenance", "--checksums-file", checksums, "--output", "-",
		"--started-on", provStartedOn, "--go-sum", "")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	var stmt provStatement
	decodeJSON(t, "provenance statement", stdout, &stmt)

	if stmt.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %q", stmt.Type)
	}

	if stmt.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("predicateType = %q, want SLSA provenance v1", stmt.PredicateType)
	}

	// Subjects must mirror the checksums file (name -> lowercased sha256).
	want := map[string]string{
		"dist/app_linux_amd64.tar.gz": strings.Repeat("a", 64),
		"dist/checksums.txt":          strings.Repeat("b", 64),
	}

	got := map[string]string{}
	for _, s := range stmt.Subject {
		got[s.Name] = s.Digest.SHA256
	}

	for name, digest := range want {
		if got[name] != digest {
			t.Errorf("subject %q digest = %q, want %q", name, got[name], digest)
		}
	}

	// Closed set: a subject vouches for an artifact, so a statement that
	// grows one the checksums file never listed is wrong even when every
	// expected subject is present.
	if len(stmt.Subject) != len(want) {
		t.Errorf("statement has %d subjects, want exactly %d: %v", len(stmt.Subject), len(want), got)
	}

	if src := stmt.Predicate.BuildDefinition.ExternalParameters["source"]; src != "git+https://github.com/fixture/example" {
		t.Errorf("externalParameters.source = %v", src)
	}

	if ref := stmt.Predicate.BuildDefinition.ExternalParameters["ref"]; ref != "v1.2.3" {
		t.Errorf("externalParameters.ref = %v", ref)
	}

	if on := stmt.Predicate.RunDetails.Metadata.StartedOn; on != provStartedOn {
		t.Errorf("startedOn = %q, want %q (pinned)", on, provStartedOn)
	}
}

// TestProvenance_Deterministic asserts two runs with identical inputs
// produce byte-identical output — the property that lets an independent
// rebuild verify the statement.
func TestProvenance_Deterministic(t *testing.T) {
	t.Parallel()

	dir, checksums := writeChecksums(t)

	args := []string{
		"release", "provenance", "--checksums-file", checksums, "--output", "-",
		"--started-on", provStartedOn, "--go-sum", "",
	}

	first, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv}, args...)
	if code != 0 {
		t.Fatalf("first run exit %d\nstderr: %s", code, stderr)
	}

	second, _, code := run(t, runOpts{dir: dir, env: provenanceEnv}, args...)
	if code != 0 {
		t.Fatalf("second run exit %d", code)
	}

	if first != second {
		t.Errorf("provenance output not deterministic across runs")
	}
}

// TestProvenance_ReservedKeyCollisionFails: --external-parameters-json may
// not shadow an engine-computed field.
func TestProvenance_ReservedKeyCollisionFails(t *testing.T) {
	t.Parallel()

	dir, checksums := writeChecksums(t)

	_, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv},
		"release", "provenance", "--checksums-file", checksums, "--output", "-",
		"--started-on", provStartedOn, "--go-sum", "",
		"--external-parameters-json", `{"source":"shadowed"}`)

	if code != exitValidation { // EX_VALIDATION: reserved-key collision
		t.Fatalf("expected EX_VALIDATION=1 for reserved-key collision, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "collision", stderr, "reserved for an engine-computed externalParameters field")
}

// TestProvenance_RefusesAnUnusableChecksumsFile covers the three input shapes
// that would otherwise yield a statement vouching for the wrong set of
// artifacts. None was exercised, and each fails for a different, correct
// reason:
//
//   - empty file  -> EX_USAGE. A provenance statement with zero subjects
//     vouches for nothing while looking structurally valid, which is the
//     worst of both.
//   - malformed line -> EX_VALIDATION, naming the offending line.
//   - one good line beside one bad one -> EX_VALIDATION, refusing the WHOLE
//     file. This is the case worth pinning: a parser that skipped the bad
//     line would emit a statement silently missing a subject, and
//     TestProvenance_GeneratesStatement's closed-set check would not see it
//     because that test's fixture has no bad lines.
func TestProvenance_RefusesAnUnusableChecksumsFile(t *testing.T) {
	t.Parallel()

	good := strings.Repeat("a", 64) + "  dist/app_linux_amd64.tar.gz\n"

	for _, tc := range []struct {
		name     string
		body     string
		wantExit int
		wantErr  string
	}{
		{"empty", "", exitUsage, "no subjects parsed from checksums"},
		{"malformed line", "not-a-checksum-line\n", exitValidation, `malformed checksum line "not-a-checksum-line"`},
		{"good line beside a bad one", good + "garbage\n", exitValidation, `malformed checksum line "garbage"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "checksums.sha256")

			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv},
				"release", "provenance", "--checksums-file", path, "--output", "-",
				"--started-on", provStartedOn, "--go-sum", "")

			if code != tc.wantExit {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, tc.wantExit, stderr)
			}

			assertContains(t, tc.name, stderr, tc.wantErr)

			// A refusal must emit no statement at all. Half a statement on
			// stdout is worse than none: a caller redirecting to a file gets
			// something that parses.
			if strings.Contains(stdout, "in-toto.io/Statement") {
				t.Errorf("a refused run still emitted a statement:\n%s", stdout)
			}
		})
	}
}

// TestProvenance_MissingChecksumFileIsNoInput fails closed when the checksums file
// doesn't exist (EX_NOINPUT).
func TestProvenance_MissingChecksumFileIsNoInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv},
		"release", "provenance", "--checksums-file", filepath.Join(dir, "nope.sha256"),
		"--output", "-", "--started-on", provStartedOn, "--go-sum", "")

	if code != exitNoInput { // EX_NOINPUT: missing checksums file
		t.Fatalf("expected EX_NOINPUT=66 for missing checksums, got %d\nstderr: %s", code, stderr)
	}

	// Named, so this cannot pass on one of the refusals above: an empty file
	// exits 2 and a malformed one exits 1, but "absent" is its own case.
	assertContains(t, "missing checksums", stderr, "nope.sha256")
}
