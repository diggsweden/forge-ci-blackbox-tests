// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `validate tag signature` accepts annotated tags signed either by
// GPG (openpgp) or by SSH (gpg.format=ssh). Both forms have to work
// because release-prerequisites accepts either — different teams use
// different signing infrastructure.
//
// Host isolation matters across this file: a developer's global
// ~/.gitconfig setting (notably gpg.format=ssh) leaking into a GPG
// test would cause git to look up an SSH key for an openpgp-format
// tag and fail with a confusing "Couldn't load public key" error.
// initGitRepo in keys_test.go pins GIT_CONFIG_GLOBAL=/dev/null per
// invocation to neutralise this.
//
// Artifact-level signing (release sign of .tgz / .jar / checksums)
// lives in release_sign_test.go.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTagSignature_GPGVerifies verifies the full GPG-signed-tag
// local pipeline as a black-box round-trip:
//
//  1. bootstrap a throwaway GPG key in an isolated GNUPGHOME
//  2. configure a fresh git repo to sign tags with it
//  3. create a signed annotated tag
//  4. run `forge-ci validate tag signature` and assert success
func TestTagSignature_GPGVerifies(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)

	env := map[string]string{"GNUPGHOME": key.gnupgHome}

	repo := initGitRepo(t, env, func(repo string, runGit func(args ...string) error) {
		makeGPGSignedTag(t, runGit, repo, key, "v1.0.0")
	})

	pub, err := os.ReadFile(key.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, runOpts{
		dir: repo,
		env: map[string]string{
			"GNUPGHOME":              key.gnupgHome,
			"RELEASE_GPG_PUBLIC_KEY": string(pub),
		},
	}, "validate", "tag", "signature", "--tag", "v1.0.0", "--repository", "fixture/integration")
	if code != 0 {
		t.Fatalf("validate tag signature exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The exit code alone proves nothing here. Without a committed allowlist,
	// enforcement is skipped by design, so failed or unavailable key verification
	// is a warning and the command still exits 0.
	//
	// The "verified" line with the fingerprint is the only output that
	// discriminates. Asserting the fingerprint too means the signature was
	// checked against this key, not merely against something.
	assertContains(t, "GPG verification", stdout+stderr, "GPG signature verified")
	assertContains(t, "GPG verification names the key", stdout+stderr, key.fingerprint)
}

// TestTagSignature_RejectsLightweight verifies that a lightweight
// (unsigned, non-annotated) tag is rejected by `validate tag
// signature`. The configure step disables tag.gpgsign locally for
// the lightweight-tag-creation step so that a global tag.gpgsign=true
// doesn't auto-promote `git tag light` into a signed tag.
func TestTagSignature_RejectsLightweight(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		mustGit(t, runGit, "config", "user.name", "Integration Test")
		mustGit(t, runGit, "config", "user.email", "integration@test.example")

		if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "README.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		// Bypass any inherited tag.gpgsign for this specific tag.
		mustGit(t, runGit, "-c", "tag.gpgsign=false", "tag", "v0.0.1-lightweight", "HEAD")
	})

	_, stderr, code := run(t, runOpts{dir: repo},
		"validate", "tag", "signature", "--tag", "v0.0.1-lightweight", "--repository", "fixture/integration")
	if code != exitValidation { // EX_VALIDATION: a lightweight tag is a policy failure, not a usage error
		t.Fatalf("validate tag signature exit = %d for lightweight tag, want 1\nstderr: %s", code, stderr)
	}

	assertContains(t, "lightweight rejection", stderr, "is a lightweight tag (not annotated)")
}

// TestTagSignature_SSHSignedTagIsAccepted guards the SSH branch of the same
// round-trip: the release pipeline must accept either signing format, and a
// gpg.format=ssh tag must be recognised as signed rather than rejected as
// unsigned.
//
// Named for what it proves. It does NOT prove the SSH signature verifies
// against an authorised signer: without a committed .forge-ci/allowed_signers
// there is no enforcement, so this test only discriminates the SSH branch.
// SSH signer verification is covered where enforcement is on —
// validate_signer_allowlist_test.go, TestReleaseAuth_SSH_AllowedSignerPasses
// and _UnknownSignerDeniedWith77 — so duplicating it here would add no claim.
//
// The wrinkle: SSH signing only works when gpg.format=ssh AND
// user.signingkey points at the ssh key path. A leftover gpg.format
// from the developer's global config would derail this, which is why
// host isolation (GIT_CONFIG_GLOBAL=/dev/null) is non-negotiable.
func TestTagSignature_SSHSignedTagIsAccepted(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		mustGit(t, runGit, "config", "gpg.ssh.allowedSignersFile", sshk.allowedSigners)
		makeSSHSignedTag(t, runGit, repo, sshk, "v2.0.0")
	})

	stdout, stderr, code := run(t, runOpts{dir: repo},
		"validate", "tag", "signature", "--tag", "v2.0.0", "--repository", "fixture/integration")
	if code != 0 {
		t.Fatalf("validate tag signature exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The validator writes human output to stderr (stdout is reserved
	// for structured emission). Check both for portability.
	//
	// This needle discriminates the SSH branch from the GPG one — the GPG path
	// prints "GPG signature" — which is the claim this test makes. It is a
	// presence marker, not a verification result; see the doc comment.
	assertContains(t, "SSH branch taken", stdout+stderr, "SSH signature")
}

// mustGit is a tiny convenience wrapper for the configure callback
// inside initGitRepo. It fails the test on any git error.
func mustGit(t *testing.T, runGit func(args ...string) error, args ...string) {
	t.Helper()

	if err := runGit(args...); err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
}
