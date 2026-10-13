// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// SSH git-object signing producer path: `release ssh setup` configures
// git for SSH signing (gpg.format=ssh + user.signingkey), so a signed
// tag created afterwards verifies via `validate tag signature`. The
// existing validate_tag_signature_test covers verification with a hand-rolled git
// config; this covers the CLI verb that produces that config, plus the
// idempotent cleanup.
package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseSSHSetup_WritesAConfigThatProducesASignedTag(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)
	keyPath := filepath.Join(t.TempDir(), "signing-key")

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# hi\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "README.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
	})

	// Producer: configure SSH signing through the CLI verb (writes the key
	// 0600 to keyPath and sets gpg.format=ssh + user.signingkey repo-locally).
	_, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"SSH_SIGNING_KEY_PATH": keyPath,
	}}, "release", "ssh", "setup",
		"--private-key-file", sshk.private,
		"--author-name", "Integration Test",
		"--author-email", "integration@test.example",
		"--git-commit-sign")
	if code != 0 {
		t.Fatalf("release ssh setup exit %d\nstderr: %s", code, stderr)
	}

	if !fileExists(keyPath) {
		t.Fatalf("setup should have written the signing key to %s", keyPath)
	}

	// The mode the comment above promises: a private signing key readable
	// by group or world defeats the point of scoping it to a file.
	if info, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("signing key mode = %o, want 0600", perm)
	}

	// Verification side: point git at allowed_signers and create a signed
	// tag using the config `release ssh setup` wrote.
	gitAt(t, repo, "config", "gpg.ssh.allowedSignersFile", sshk.allowedSigners)
	gitAt(t, repo, "tag", "-s", "-m", "release v3.0.0", "v3.0.0")

	stdout, stderr, code := run(t, runOpts{dir: repo},
		"validate", "tag", "signature", "--tag", "v3.0.0", "--repository", "diggsweden/integration")
	if code != 0 {
		t.Fatalf("validate tag signature exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The needle discriminates the SSH branch from the GPG one, which is the
	// claim here: the config `release ssh setup` wrote made git produce a tag
	// the validator recognises as SSH-signed.
	//
	// It is a presence marker, not a verification result — without a committed
	// .forge-ci/allowed_signers the validator skips enforcement and exits 0
	// either way (see validate_tag_signature_test.go). Cryptographic SSH signer
	// verification is covered under enforcement in
	// validate_signer_allowlist_test.go; this test is about the producer verb.
	assertContains(t, "SSH branch taken", stdout+stderr, "SSH signature")

	// Cleanup is idempotent and safe under if: always().
	for i := range 2 {
		if _, errOut, c := run(t, runOpts{dir: repo, env: map[string]string{"SSH_SIGNING_KEY_PATH": keyPath}},
			"release", "ssh", "cleanup"); c != 0 {
			t.Fatalf("release ssh cleanup (run %d) exit %d\n%s", i+1, c, errOut)
		}
	}

	if fileExists(keyPath) {
		t.Errorf("cleanup should have removed the signing key at %s", keyPath)
	}
}
