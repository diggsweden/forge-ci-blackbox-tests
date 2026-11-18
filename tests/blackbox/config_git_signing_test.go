// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// git-signing config dimension and its exposure in the typed config
// plan. The `git-signing:` block selects how the release commit/tag are
// signed (gpg default, or ssh), independent of artifact signing. The
// plan also precomputes the signing-method flags the workflows gate on.
package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// gitSigningPlan is the part of the config plan the git-signing tests read.
type gitSigningPlan struct {
	GitSigning struct {
		Method string `json:"method"`
	} `json:"git_signing"`
	Sign struct {
		Method        string `json:"method"`
		ImportsGPGKey bool   `json:"imports_gpg_key"`
	} `json:"sign"`
}

// parseConfigPlan returns the decoded config plan for repo.
func parseConfigPlan(t *testing.T, repo string) gitSigningPlan {
	t.Helper()

	var plan gitSigningPlan
	decodeJSON(t, "config plan", configPlanJSON(t, repo), &plan)

	return plan
}

// writeArtifactsRepo lays out a temp repo with the given artifacts.yml
// under .forge-ci/. Shared by the git-signing and doctor tests.
func writeArtifactsRepo(t *testing.T, artifactsYAML string) string {
	t.Helper()

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, ".forge-ci", "artifacts.yml"), []byte(artifactsYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	return repo
}

// TestGitSigning_PlanExposesSSHMethod verifies a `git-signing: method:
// ssh` block is parsed and surfaced in the config plan, and that the
// default sign method's precomputed flags are emitted.
func TestGitSigning_PlanExposesSSHMethod(t *testing.T) {
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

	plan := parseConfigPlan(t, repo)

	if plan.GitSigning.Method != "ssh" {
		t.Errorf("git_signing.method = %q, want ssh", plan.GitSigning.Method)
	}

	// Default sign method is gpg → imports the key.
	if !plan.Sign.ImportsGPGKey {
		t.Errorf("sign.imports_gpg_key = false, want true for the gpg default")
	}
}

// TestGitSigning_DefaultsToGPG verifies that omitting the git-signing
// block yields method=gpg in the plan (the unchanged default).
func TestGitSigning_DefaultsToGPG(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
`)

	plan := parseConfigPlan(t, repo)

	if plan.GitSigning.Method != "gpg" {
		t.Errorf("git_signing.method = %q, want gpg (the default)", plan.GitSigning.Method)
	}
}

// TestGitSigning_RejectsUnknownMethod verifies the schema rejects a
// git-signing method other than gpg/ssh (gitsign is intentionally not
// supported).
func TestGitSigning_RejectsUnknownMethod(t *testing.T) {
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

	_, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "config", "parse-artifacts")
	if code != exitConfig {
		t.Fatalf("git-signing.method=gitsign exit = %d, want %d (EX_CONFIG)\nstderr: %s", code, exitConfig, stderr)
	}

	assertContains(t, "names the field, the value and the accepted set", stderr, `git-signing.method "gitsign" is not one of [gpg, ssh]`)
}
