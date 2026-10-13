// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `release dist-digest` and `release
// prepare-dist` — the release hand-off digest. dist-digest prints the
// SHA-256 of the sorted sha256sum manifest for a dist directory, byte-
// compatible with forgejo-ci's dist-digest.sh; prepare-dist prunes and
// digests the hand-off and emits digest=<sha> to the CI output sink
// before upload. The tests assert tamper detection, the shell-pipeline
// byte-compatibility contract through --manifest-root, and that
// prepare-dist emits the same digest dist-digest computes. That path
// spelling changes the default digest, and that --manifest-root . makes
// it path-independent, are unit tests in forge-ci's
// internal/app/release.

package blackbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// distDigest runs `release dist-digest <args>` and returns the bare hex
// digest, failing on a non-zero exit.
func distDigest(t *testing.T, args ...string) string {
	t.Helper()

	stdout, stderr, code := run(t, runOpts{}, append([]string{"release", "dist-digest"}, args...)...)
	if code != 0 {
		t.Fatalf("release dist-digest %v exit %d\nstderr: %s", args, code, stderr)
	}

	return strings.TrimSpace(stdout)
}

// shellDistDigest reproduces forgejo-ci's dist-digest.sh pipeline against
// dir, under LC_ALL=C so the sort order matches the Go implementation.
func shellDistDigest(t *testing.T, dir string) string {
	t.Helper()
	requireTool(t, "sha256sum")
	requireTool(t, "bash")

	cmd := toolCommand(t, dir, map[string]string{"LC_ALL": "C"},
		"bash", "-c", "set -o pipefail; find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum")

	fields := strings.Fields(outputOrFatal(t, cmd))
	if len(fields) == 0 {
		t.Fatal("empty shell pipeline output")
	}

	return fields[0]
}

// TestDistDigest_DetectsTamper: a one-byte content change flips the
// digest.
func TestDistDigest_DetectsTamper(t *testing.T) {
	t.Parallel()

	dir := writeDigestTree(t, map[string]string{"app.tar.gz": "payload", "checksums.txt": "sums"})

	before := distDigest(t, "--dist-dir", dir)

	if err := os.WriteFile(filepath.Join(dir, "app.tar.gz"), []byte("payloadX"), 0o644); err != nil {
		t.Fatal(err)
	}

	if after := distDigest(t, "--dist-dir", dir); after == before {
		t.Errorf("content change not reflected in dist-digest (%s)", before)
	}
}

// TestDistDigest_ByteCompatibleWithShellPipeline pins the documented
// contract: the digest equals forgejo-ci's dist-digest.sh pipeline. It is
// also the one test that passes --manifest-root through the CLI.
func TestDistDigest_ByteCompatibleWithShellPipeline(t *testing.T) {
	t.Parallel()

	requireTool(t, "sha256sum")
	requireTool(t, "bash")

	dir := writeDigestTree(t, map[string]string{
		"app_linux_amd64.tar.gz": "amd64", "app_linux_arm64.tar.gz": "arm64",
		"checksums.txt": "sums", "nested/extra.txt": "more",
	})

	// --manifest-root . makes the manifest paths ("./app...") match what
	// `cd dir && find . -type f` emits.
	got := distDigest(t, "--dist-dir", dir, "--manifest-root", ".")
	want := shellDistDigest(t, dir)

	if got != want {
		t.Errorf("dist-digest %s != shell pipeline %s", got, want)
	}
}

// TestDistDigest_RejectsEmptyTree: an empty hand-off is refused rather
// than digested to the empty-tree hash.
func TestDistDigest_RejectsEmptyTree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, stderr, code := run(t, runOpts{}, "release", "dist-digest", "--dist-dir", dir)

	if code != exitValidation { // EX_VALIDATION: empty hand-off
		t.Fatalf("expected EX_VALIDATION=1 for empty dist dir, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "empty dist", stderr, "no files under")
}

// TestPrepareDist_EmitsDigestMatchingDistDigest: prepare-dist writes
// digest=<sha> to the CI output sink, and that digest equals what
// dist-digest computes for the same contents (prune-dirs false).
func TestPrepareDist_EmitsDigestMatchingDistDigest(t *testing.T) {
	t.Parallel()

	dir := writeDigestTree(t, map[string]string{"release.txt": "payload", "nested/extra.txt": "more"})
	out := ghaOutputFile(t)

	// prepare-dist refuses any path that is not a strict descendant of its
	// working directory, so run it from the dist dir's parent. The path stays
	// absolute: the digest manifest folds the path spelling in (see
	// DistDigestWithManifestRoot), and dist-digest below spells it the same way.
	_, stderr, code := run(t, runOpts{dir: filepath.Dir(dir), env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": out}},
		"release", "prepare-dist", "--path", dir, "--prune-dirs", "false")
	if code != 0 {
		t.Fatalf("prepare-dist exit %d\nstderr: %s", code, stderr)
	}

	got := parseGHAOutputs(t, out)["digest"]
	if len(got) != 64 { //nolint:mnd // sha256 hex length
		t.Fatalf("prepare-dist emitted digest = %q, want 64-hex", got)
	}

	if want := distDigest(t, "--dist-dir", dir); got != want {
		t.Errorf("prepare-dist digest %s != dist-digest %s", got, want)
	}
}

// TestPrepareDist_PrunesTopLevelDirs: --prune-dirs true removes top-level
// directories before digesting, and the emitted digest reflects the
// pruned (files-only) tree.
func TestPrepareDist_PrunesTopLevelDirs(t *testing.T) {
	t.Parallel()

	dir := writeDigestTree(t, map[string]string{"release.txt": "payload", "raw/binary": "rawbytes"})
	out := ghaOutputFile(t)

	// Same strict-descendant rule and same-spelling requirement as above.
	_, stderr, code := run(t, runOpts{dir: filepath.Dir(dir), env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": out}},
		"release", "prepare-dist", "--path", dir, "--prune-dirs", "true")
	if code != 0 {
		t.Fatalf("prepare-dist exit %d\nstderr: %s", code, stderr)
	}

	if _, err := os.Stat(filepath.Join(dir, "raw")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--prune-dirs true did not remove top-level dir raw/ (stat err: %v)", err)
	}

	got := parseGHAOutputs(t, out)["digest"]
	if want := distDigest(t, "--dist-dir", dir); got != want {
		t.Errorf("pruned prepare-dist digest %s != dist-digest of pruned tree %s", got, want)
	}
}
