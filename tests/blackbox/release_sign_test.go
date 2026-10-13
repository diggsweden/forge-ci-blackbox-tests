// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Release-flow artifact signing: SHA256 manifest generation +
// GPG detached signatures over the manifest and the artifacts it
// references.
//
// Tag-signature verification (the other "signing" surface) lives in
// validate_tag_signature_test.go.
//
// Version-bump coverage lives in version_bump_matrix_test.go.

package blackbox

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestChecksums_RoundTripAndComplete verifies that the SHA256 manifest produced
// by `release checksums` round-trips through the standard
// sha256sum --check verifier, and that the bug fix preventing the
// manifest from including itself (empty-file SHA self-poison) holds.
func TestChecksums_RoundTripAndComplete(t *testing.T) {
	t.Parallel()

	requireTool(t, "sha256sum")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app-linux-amd64"), []byte("payload-a"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "app-darwin-arm64"), []byte("payload-b"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{dir: dir},
		"release", "checksums", "--release-artifacts-dir", ".")
	if code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	manifest := filepath.Join(dir, "checksums.sha256")
	if !fileExists(manifest) {
		t.Fatalf("manifest missing")
	}

	if slices.Contains(checksumManifestNames(t, manifest), "checksums.sha256") {
		t.Errorf("manifest contains a line for itself (regression of self-poison bug)")
	}

	// Completeness: sha256sum --check only verifies the lines that are
	// present, so a manifest that silently dropped an artifact would still
	// round-trip. Every artifact must have a line.
	assertChecksumManifestLists(t, manifest, "app-linux-amd64", "app-darwin-arm64")

	cmd := toolCommand(t, dir, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("sha256sum --check failed: %v\n%s", err, out)
	}
}

// TestReleaseSign_WarnsOnEmptyMatch verifies the bug fix that prevents
// `release sign` from silently exiting 0 with zero signatures when
// every file in --release-artifacts-dir fails the extension filter
// (bare binaries — which need --attach-artifacts instead).
func TestReleaseSign_WarnsOnEmptyMatch(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app-linux-amd64"), []byte("bare"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: key.signingEnv(t),
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")
	if code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	// sign writes its info to stderr.
	assertContains(t, "filter excludes everything", stderr, "no files in")
}

// TestReleaseSign_GPGSignsAndVerifies verifies a real GPG sign+verify cycle of an
// archive-extension artifact. Host isolation matters: the developer's
// global ~/.gitconfig may set gpg.format=ssh which would otherwise
// break GPG signing entirely.
func TestReleaseSign_GPGSignsAndVerifies(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	// The one RSA row: every other GPG row signs with ed25519.
	key := bootstrapRSAGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("archive payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{
		dir: dir,
		env: key.signingEnv(t),
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")
	if code != 0 {
		t.Fatalf("sign exit %d", code)
	}

	sig := filepath.Join(dir, "app.tgz.asc")
	if !fileExists(sig) {
		t.Fatalf("expected detached signature at %s", sig)
	}

	cmd := toolCommand(t, dir, map[string]string{"GNUPGHOME": key.gnupgHome},
		"gpg", "--verify", sig, filepath.Join(ra, "app.tgz"))

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("gpg --verify failed: %v\n%s", err, out)
	}
}
