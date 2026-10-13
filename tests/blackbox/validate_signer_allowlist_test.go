// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Local black-box coverage for release authorisation: the project commits
// .forge-ci/allowed_signers (SSH) or .forge-ci/allowed_gpg_keys.asc
// (GPG); `forge-ci validate tag signature --require-allowlisted-signer`
// then enforces that the tag's signing key appears in the relevant file.
// Each GPG file is self-verifying — the committed public keys are both
// the verification material and the authorised set. Denied releases exit
// with EX_NOPERM (77) — distinct from validation (1) and usage (2).
//
// Tag-signature happy-path coverage (signed = ok, no enforcement) lives
// in validate_tag_signature_test.go; this file is exclusively about the allowlist
// gate.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runValidateTagSignature is a small wrapper around the CLI call —
// every test in this file uses the same shape, so collapsing it cuts
// boilerplate without hiding behaviour.
func runValidateTagSignature(t *testing.T, dir, tag string, requireAllowlistedSigner bool, env map[string]string) (stdout, stderr string, exitCode int) {
	t.Helper()

	args := []string{"validate", "tag", "signature", "--tag", tag, "--repository", "diggsweden/integration"}
	if requireAllowlistedSigner {
		args = append([]string{"--format", "github"}, args...)
		env = mergeEnv(env, map[string]string{"REQUIRE_ALLOWLISTED_SIGNER": "true"})
	}

	return run(t, runOpts{dir: dir, env: env}, args...)
}

// TestReleaseAuth_SSH_AllowedSignerPasses creates a repo with an
// allowed_signers file containing the signing key, signs a tag with
// that key, runs the validator with --require-allowlisted-signer, and
// asserts success.
func TestReleaseAuth_SSH_AllowedSignerPasses(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		writeAllowedSigners(t, repo, "integration@test.example", sshk)
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "cites the allowlist file", stderr, ".forge-ci/allowed_signers")
}

// TestReleaseAuth_SSH_UnknownSignerDeniedWith77 mirrors the happy
// path but the allowed_signers file does NOT contain the signing key.
// Expected: exit 77 (EX_NOPERM) + "No principal matched" in output.
func TestReleaseAuth_SSH_UnknownSignerDeniedWith77(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		// Allowlist exists but lists a DIFFERENT signer key.
		if err := os.MkdirAll(filepath.Join(repo, ".forge-ci"), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(
			filepath.Join(repo, ".forge-ci", "allowed_signers"),
			[]byte("eve@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEVERMATCHEVERMATCHEVERMATCHEVERMATCH integration@test.example\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}

		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != exitNoPerm { // EX_NOPERM (sysexits.h §EX_NOPERM)
		t.Errorf("expected EX_NOPERM=77 for unknown signer, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "explains the denial", stderr, "signature is valid but signer is not in allowed_signers")
}

// TestReleaseAuth_SSH_MissingAllowlistFailsClosed checks the
// fail-closed behaviour: --require-allowlisted-signer + no
// .forge-ci/allowed_signers → EX_NOPERM, not silent pass.
func TestReleaseAuth_SSH_MissingAllowlistFailsClosed(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	// No allowlist file is created.
	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != exitNoPerm { // EX_NOPERM
		t.Errorf("expected EX_NOPERM=77 when allowlist missing AND require=true; got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "explains the missing allowlist", stderr, "tag signature verification requires .forge-ci/allowed_signers")
}

// TestReleaseAuth_SSH_MissingAllowlistTolerated checks the
// opt-out path: --require-allowlisted-signer=false + no allowlist file
// → exit 0 (the project didn't opt in; we don't fail closed).
func TestReleaseAuth_SSH_MissingAllowlistTolerated(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	stdout, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", false, nil)
	if code != 0 {
		t.Errorf("expected exit 0 when require=false and no allowlist; got %d\nstderr: %s", code, stderr)
	}

	// Exit 0 holds with or without a signature here; the SSH branch must run.
	assertContains(t, "SSH branch", stdout+stderr, "Tag has an SSH signature")
}

// TestReleaseAuth_GPG_AllowedKeyPasses creates a GPG-signed tag, commits
// the signer's public key to .forge-ci/allowed_gpg_keys.asc, and
// asserts success. The committed bundle is self-verifying — both the
// verification material and the authorised set — so no RELEASE_GPG_PUBLIC_KEY
// is needed.
func TestReleaseAuth_GPG_AllowedKeyPasses(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)

	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		writeAllowedGPGKeys(t, repo, key.publicASC)
		makeGPGSignedTag(t, runGit, repo, key, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, map[string]string{
		"GNUPGHOME": key.gnupgHome,
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "names the signing fingerprint", stderr, key.fingerprint)
}

// TestReleaseAuth_GPG_UnknownKeyDeniedWith77 commits a DIFFERENT key to
// allowed_gpg_keys.asc. The signer's key verifies (supplied via
// RELEASE_GPG_PUBLIC_KEY) but its fingerprint isn't in the authorised
// set; expected: exit 77.
func TestReleaseAuth_GPG_UnknownKeyDeniedWith77(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)
	other := bootstrapGPGKey(t)

	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		// Allowlist authorises an unrelated key, not the signer's.
		writeAllowedGPGKeys(t, repo, other.publicASC)
		makeGPGSignedTag(t, runGit, repo, key, "v1.0.0")
	})

	pub, err := os.ReadFile(key.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, map[string]string{
		"GNUPGHOME":              key.gnupgHome,
		"RELEASE_GPG_PUBLIC_KEY": string(pub),
	})
	if code != exitNoPerm { // EX_NOPERM
		t.Errorf("expected EX_NOPERM=77 for unauthorised key, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "explains the denial", stderr, "not authorised")
}

// TestReleaseAuth_GPG_RotationBundleAuthorisesTheAppendedKey covers key
// rotation through the documented workflow: docs/verification.md tells
// operators to add a key with `gpg --armor --export <email> >>
// allowed_gpg_keys.asc`, which appends a SECOND armor block. During a rotation
// the file deliberately holds two keys, and the incoming one is the appended
// block — so a reader that stops at the first block silently authorises only
// the outgoing key and refuses the release it was set up to allow.
//
// The engine tier already pins the parsing
// (openpgp.TestPrimaryFingerprints_ReadsEveryConcatenatedBlock and
// validate.TestTagSignature_GPG_AllowlistHonoursEveryConcatenatedBlock). This
// is the operator-facing half: a real committed .forge-ci bundle, a real
// signed tag, through the compiled binary. Mutation-verified — capping the
// armor scan at the first block fails this test and nothing else out here.
func TestReleaseAuth_GPG_RotationBundleAuthorisesTheAppendedKey(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	requireTool(t, "git")

	outgoing := bootstrapGPGKey(t)
	incoming := bootstrapGPGKey(t)

	// Sign with the INCOMING key — the one in the appended block.
	repo := initGitRepo(t, map[string]string{"GNUPGHOME": incoming.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		writeAllowedGPGKeys(t, repo, outgoing.publicASC, incoming.publicASC)
		makeGPGSignedTag(t, runGit, repo, incoming, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, map[string]string{
		"GNUPGHOME": incoming.gnupgHome,
	})
	if code != 0 {
		t.Fatalf("a key in the appended block was not authorised: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "names the appended signing fingerprint", stderr, incoming.fingerprint)

	// The bundle must not become an authorise-anything file: a third key that
	// is in neither block is still refused.
	stranger := bootstrapGPGKey(t)

	strangerRepo := initGitRepo(t, map[string]string{"GNUPGHOME": stranger.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		writeAllowedGPGKeys(t, repo, outgoing.publicASC, incoming.publicASC)
		makeGPGSignedTag(t, runGit, repo, stranger, "v1.0.0")
	})

	pub, err := os.ReadFile(stranger.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	if _, stderr, code = runValidateTagSignature(t, strangerRepo, "v1.0.0", true, map[string]string{
		"GNUPGHOME":              stranger.gnupgHome,
		"RELEASE_GPG_PUBLIC_KEY": string(pub),
	}); code != exitNoPerm {
		t.Errorf("a key in neither block was accepted: exit %d, want 77\nstderr: %s", code, stderr)
	}

	assertContains(t, "stranger denied", stderr, "not authorised")
}

// writeAllowedSigners drops the SSH key's public material at
// .forge-ci/allowed_signers in the canonical OpenSSH format.
func writeAllowedSigners(t *testing.T, repo, principal string, sshk sshKey) {
	t.Helper()

	pub, err := os.ReadFile(sshk.public)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(repo, ".forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	line := principal + " " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(filepath.Join(repo, ".forge-ci", "allowed_signers"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeAllowedGPGKeys copies an armored public key into
// .forge-ci/allowed_gpg_keys.asc — the single GPG allowlist file,
// which is both the verification material and the authorised set.
func writeAllowedGPGKeys(t *testing.T, repo string, publicASCPaths ...string) {
	t.Helper()

	// Concatenated, exactly as docs/verification.md tells operators to add a
	// key: `gpg --armor --export <email> >> allowed_gpg_keys.asc`. One path is
	// the ordinary case; more than one is the rotation bundle.
	var bundle []byte

	for _, path := range publicASCPaths {
		pub, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		bundle = append(bundle, pub...)
	}

	if err := os.MkdirAll(filepath.Join(repo, ".forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, ".forge-ci", "allowed_gpg_keys.asc"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeSSHSignedTag configures git to sign with the bootstrapped SSH
// key, commits a placeholder file, and creates an annotated signed
// tag at HEAD.
func makeSSHSignedTag(t *testing.T, runGit func(args ...string) error, repo string, sshk sshKey, tag string) {
	t.Helper()

	mustGit(t, runGit, "config", "user.name", "Integration Test")
	mustGit(t, runGit, "config", "user.email", "integration@test.example")
	mustGit(t, runGit, "config", "gpg.format", "ssh")
	mustGit(t, runGit, "config", "user.signingkey", sshk.private)
	mustGit(t, runGit, "config", "tag.gpgsign", "true")

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Release auth fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mustGit(t, runGit, "add", "README.md")
	mustGit(t, runGit, "commit", "-q", "-m", "initial")
	mustGit(t, runGit, "tag", "-s", "-m", "release "+tag, tag)
}

// makeGPGSignedTag is the GPG counterpart of makeSSHSignedTag.
func makeGPGSignedTag(t *testing.T, runGit func(args ...string) error, repo string, key gpgKey, tag string) {
	t.Helper()

	mustGit(t, runGit, "config", "user.name", "Integration Test")
	mustGit(t, runGit, "config", "user.email", "integration@test.example")
	mustGit(t, runGit, "config", "gpg.format", "openpgp")
	mustGit(t, runGit, "config", "user.signingkey", key.keyID)
	mustGit(t, runGit, "config", "tag.gpgsign", "true")

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Release auth fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mustGit(t, runGit, "add", "README.md")
	mustGit(t, runGit, "commit", "-q", "-m", "initial")
	mustGit(t, runGit, "tag", "-s", "-m", "release "+tag, tag)
}
