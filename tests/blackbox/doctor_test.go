// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// `forge-ci doctor` setup checks: the keyless signing recommendation
// (gpg + a keyless-capable forge) and the SSH git-signing allowlist
// check. Both are non-failing (warnings/advisories) so doctor exits 0 —
// and one failing check pins the other side of that boundary, so a
// doctor that stopped looking at anything could not pass this file. The
// negative controls (no recommendation on a keyless repo, OK with an
// allowlist) are unit tests in forge-ci's internal/app/doctor.
package blackbox

import "testing"

// TestDoctor_RecommendsKeylessOnGPG verifies doctor suggests
// sigstore-keyless when the repo signs artifacts with gpg, the detected
// forge supports keyless (GitHub), and nothing publishes to a PGP-native
// registry.
func TestDoctor_RecommendsKeylessOnGPG(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
`) // no sign block → gpg default; no maven-central publish

	stdout, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "fixture/integration",
	}}, "doctor", "--root", ".")

	// doctor exits 0 for advisories/warnings.
	if code != 0 {
		t.Fatalf("doctor should exit 0 for advisories; got %d\nstderr: %s", code, stderr)
	}

	// Not `strings.Contains(out, "keyless")`: doctor's capability matrix prints
	// "[yes] keyless OIDC signing (public Fulcio)" on every run
	// regardless of what the repo signs with, so that check passes with the
	// recommendation deleted. The recommendation is its own labelled check.
	out := stdout + stderr
	assertContains(t, "keyless recommendation", out, "signing method recommendation")
	assertContains(t, "names the method to move to", out, "sign.method: sigstore")
}

// TestDoctor_SSHGitSigningWarnsWithoutAllowlist verifies doctor warns
// when git-signing.method=ssh but .forge-ci/allowed_signers is
// absent (SSH-signed tags can't be verified without it).
func TestDoctor_SSHGitSigningWarnsWithoutAllowlist(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
git-signing:
  method: ssh
`)

	stdout, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "fixture/integration",
	}}, "doctor", "--root", ".")

	// The allowlist check is a warning, not a failure.
	if code != 0 {
		t.Fatalf("doctor should exit 0 (warning, not fail); got %d\nstderr: %s", code, stderr)
	}

	// The warning line itself, not the file name: doctor names allowed_signers
	// in the check's OK line and in its hint too, so the bare name is printed
	// whether or not the warning fired.
	assertContains(t, "allowlist warning", stdout+stderr, "[WARN] ssh git-signing allowlist")
}

// TestDoctor_FailingCheckExitsNonZero pins the advisory/fail boundary
// from the failing side: an artifacts.yml that fails validation is a
// SeverityFail check, and doctor must exit 1 naming the count — not
// bury it in prose that exits 0 like the advisories above.
func TestDoctor_FailingCheckExitsNonZero(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
git-signing:
  method: gitsign
`)

	stdout, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "fixture/integration",
	}}, "doctor", "--root", ".")

	if code != exitValidation { // EX_VALIDATION: failing doctor check
		t.Fatalf("doctor with a failing check: exit %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	assertContains(t, "doctor failure count", stdout+stderr, "failing check(s)")
}
