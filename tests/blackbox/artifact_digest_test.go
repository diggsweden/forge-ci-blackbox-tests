// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `artifact digest` — a canonical content digest
// over a directory, committing to each file's path, execute bit, size and
// contents.
//
// This is NOT the build->sign hand-off digest, despite being the obvious
// candidate for it. That is `release dist-digest` / `release validate-dist`
// (see release_dist_digest_test.go): a different, sha256sum-compatible
// scheme, and the pair actually wired into the cross-job tamper-evidence
// channel, where the producer emits the digest as a job output and the
// signer re-derives and compares. `artifact digest` has no caller in the
// engine's own workflows or in forgejo-ci; it is offered to adopters who
// want a strict content digest inside their own flow.
//
// The tests assert the properties this verb does have: the digest is
// reproducible across runners (it ignores dir location and mtime), and any
// content or exec-bit change flips it.

package blackbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDigestTree writes files (relpath -> content) into a fresh temp
// dir, creating parent directories, and returns the dir. Shared by the
// digest tests.
func writeDigestTree(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// touchTree sets the mtime of every regular file under dir to when, to
// prove the digest doesn't depend on timestamps.
func touchTree(t *testing.T, dir string, when time.Time) {
	t.Helper()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		return os.Chtimes(path, when, when)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// artifactDigest runs `artifact digest --dir dir` and returns the bare
// hex digest, failing on a non-zero exit.
func artifactDigest(t *testing.T, dir string) string {
	t.Helper()

	stdout, stderr, code := run(t, runOpts{}, "artifact", "digest", "--dir", dir)
	if code != 0 {
		t.Fatalf("artifact digest exit %d\nstderr: %s", code, stderr)
	}

	return strings.TrimSpace(stdout)
}

// TestArtifactDigest_ReproducibleIgnoresLocationAndMtime: the same content
// in two different directories, with different file mtimes, must yield
// the same digest — otherwise the signer couldn't re-derive what the
// builder recorded.
func TestArtifactDigest_ReproducibleIgnoresLocationAndMtime(t *testing.T) {
	t.Parallel()

	files := map[string]string{"a.txt": "alpha", "sub/b.txt": "bravo", "empty": ""}

	dirA := writeDigestTree(t, files)
	dirB := writeDigestTree(t, files)
	touchTree(t, dirA, time.Unix(1_000_000_000, 0))
	touchTree(t, dirB, time.Unix(1_700_000_000, 0))

	da, db := artifactDigest(t, dirA), artifactDigest(t, dirB)

	if len(da) != 64 { //nolint:mnd // sha256 hex length
		t.Fatalf("digest not a 64-hex sha256: %q", da)
	}

	if da != db {
		t.Errorf("digest not reproducible across location/mtime: %s vs %s", da, db)
	}
}

// TestArtifactDigest_DetectsContentChange: flipping one content byte, and
// adding a file, each change the digest. Contrast
// TestDistDigest_DetectsTamper, which keeps the stronger name because that
// digest is the one carried out of band and compared by the signer.
func TestArtifactDigest_DetectsContentChange(t *testing.T) {
	t.Parallel()

	files := map[string]string{"a.txt": "alpha", "sub/b.txt": "bravo"}
	dir := writeDigestTree(t, files)

	before := artifactDigest(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alphaX"), 0o644); err != nil {
		t.Fatal(err)
	}

	tampered := artifactDigest(t, dir)
	if tampered == before {
		t.Errorf("content change not reflected in digest (%s)", before)
	}

	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte("charlie"), 0o644); err != nil {
		t.Fatal(err)
	}

	added := artifactDigest(t, dir)
	if added == tampered {
		t.Errorf("added file not reflected in digest (%s)", tampered)
	}
}

// TestArtifactDigest_ExecBitSignificant: the same bytes with the execute
// bit set must digest differently, so flipping a shipped script to
// executable can't slip past the signature.
func TestArtifactDigest_ExecBitSignificant(t *testing.T) {
	t.Parallel()

	dir1 := writeDigestTree(t, map[string]string{"run.sh": "#!/bin/sh\necho hi\n"})
	dir2 := writeDigestTree(t, map[string]string{"run.sh": "#!/bin/sh\necho hi\n"})

	if err := os.Chmod(filepath.Join(dir2, "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	if artifactDigest(t, dir1) == artifactDigest(t, dir2) {
		t.Errorf("exec-bit change not reflected in digest")
	}
}

// TestArtifactDigest_MissingDirIsUsageError: --dir is required; omitting
// it is a caller mistake, not a validation failure.
func TestArtifactDigest_MissingDirIsUsageError(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{}, "artifact", "digest")

	if code != exitUsage { // EX_USAGE: required flag missing
		t.Fatalf("expected EX_USAGE=2 when --dir omitted, got %d\nstderr: %s", code, stderr)
	}

	// The whole sentence, not the substring "dir": a --dir pointing at a
	// missing directory also fails with "dir" in its message ("no such file
	// or directory"), so the short needle cannot tell the two apart and the
	// exit code was carrying this assertion alone.
	assertContains(t, "usage", stderr, `Required flag "dir" not set`)
}
