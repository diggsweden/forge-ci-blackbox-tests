// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the `release files` verbs: the publish allowlist
// that decides which dist/ files become public release assets, and the
// checksums-file cross-checks the signer runs before publishing. It verifies
// that internal evidence does not enter the public release manifest.
package blackbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// releaseFilesFixture writes a dist/ tree mixing public release assets with
// internal evidence that must never be published, plus the goreleaser
// artifacts.json the collector reads. Returns the fixture root.
func releaseFilesFixture(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	dist := filepath.Join(root, "dist")

	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}

	files := []string{
		"app.tar.gz",
		"app.deb", "app.deb.sig",
		"app.rpm", "app.rpm.sig",
		"app.apk", "app.apk.sig",
		"app.tar.gz.sbom.json", "app.tar.gz.sbom.json.bundle",
		"app_checksums.txt", "app_checksums.txt.bundle",
		"slsa-provenance.intoto.json", "slsa-provenance.intoto.json.bundle",
		"image-sbom.cyclonedx.json", "image-sbom.cyclonedx.json.bundle",
		"trivy-results-core-amd64.json", "trivy-results-core-amd64.json.bundle",
		"doctor-core.json", "doctor-core.json.bundle",
		"stray.sbom.json", "stray.sbom.json.bundle",
		"metadata.json", "internal-binary",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Real digests: validate-checksums re-hashes the files.
	var checksums strings.Builder
	for _, name := range []string{"app.tar.gz", "app.deb", "app.rpm", "app.apk", "app.tar.gz.sbom.json"} {
		fmt.Fprintf(&checksums, "%s  %s\n", sha256File(t, filepath.Join(dist, name)), name)
	}

	if err := os.WriteFile(filepath.Join(dist, "app_checksums.txt"), []byte(checksums.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	artifacts := `[
  {"path": "dist/app.tar.gz", "type": "Archive"},
  {"path": "dist/app.deb", "type": "LinuxPackage"},
  {"path": "dist/app.rpm", "type": "LinuxPackage"},
  {"path": "dist/app.apk", "type": "LinuxPackage"},
  {"path": "dist/app.tar.gz.sbom.json", "type": "SBOM"},
  {"path": "dist/app_checksums.txt", "type": "Checksum"},
  {"path": "dist/metadata.json", "type": "Metadata"},
  {"path": "dist/internal-binary", "type": "Binary"}
]`
	if err := os.WriteFile(filepath.Join(dist, "artifacts.json"), []byte(artifacts), 0o600); err != nil {
		t.Fatal(err)
	}

	return root
}

func assetNames(t *testing.T, assetsJSON string) map[string]bool {
	t.Helper()

	var doc struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.Unmarshal([]byte(readFile(t, assetsJSON)), &doc); err != nil {
		t.Fatalf("parse %s: %v", assetsJSON, err)
	}

	names := map[string]bool{}
	for _, a := range doc.Assets {
		names[a.Name] = true
	}

	return names
}

func TestReleaseFiles_AllowlistPublishesOnlyPublicAssets(t *testing.T) {
	t.Parallel()

	root := releaseFilesFixture(t)
	manifest := "dist/forgejo-ci-release-files.json"

	_, stderr, code := run(t, runOpts{dir: root},
		"release", "files", "collect", "--manifest", manifest, "--output", "assets.json")
	if code != 0 {
		t.Fatalf("collect exit %d\nstderr: %s", code, stderr)
	}

	names := assetNames(t, filepath.Join(root, "assets.json"))

	wanted := map[string]bool{}
	for _, want := range []string{
		"app.tar.gz",
		"app.deb", "app.deb.sig",
		"app.rpm", "app.rpm.sig",
		"app.apk", "app.apk.sig",
		"app.tar.gz.sbom.json", "app.tar.gz.sbom.json.bundle",
		"app_checksums.txt", "app_checksums.txt.bundle",
		"slsa-provenance.intoto.json", "slsa-provenance.intoto.json.bundle",
	} {
		wanted[want] = true

		if !names[want] {
			t.Errorf("public asset missing from collect output: %s", want)
		}
	}

	// The other side of the allowlist, as a CLOSED set: evidence
	// (doctor-*), container SBOMs (image-sbom.*), scan results (trivy-*),
	// and unlisted files (stray.sbom.json, metadata.json, internal-binary)
	// must never become release assets -- and neither may anything the
	// fixture didn't anticipate, artifacts.json itself included.
	for name := range names {
		if !wanted[name] {
			t.Errorf("internal file leaked into release assets: %s", name)
		}
	}

	// The manifest records the evidence classes for the signer.
	_, stderr, code = run(t, runOpts{dir: root},
		"release", "files", "manifest", "--manifest", manifest, "--assets-json", "assets.json")
	if code != 0 {
		t.Fatalf("manifest exit %d\nstderr: %s", code, stderr)
	}

	// A named manifest has to exist, so the checksums are validated against
	// the one just written.
	_, stderr, code = run(t, runOpts{dir: root},
		"release", "files", "validate-checksums", "--manifest", manifest,
		"--checksums-file", "dist/app_checksums.txt")
	if code != 0 {
		t.Fatalf("validate-checksums exit %d\nstderr: %s", code, stderr)
	}

	type manifestEntry struct {
		Name string `json:"name"`
	}

	var m struct {
		Checksums  []manifestEntry `json:"checksums"`
		SBOMs      []manifestEntry `json:"sboms"`
		Evidence   []manifestEntry `json:"evidence"`
		Provenance []manifestEntry `json:"provenance"`
	}

	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(root, manifest))), &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	// WHICH file landed in each class, not just how many. The signer reads
	// these classes to decide what to sign and how, so a classifier that swapped
	// checksum and SBOM entries must fail even when the class counts still match.
	for _, tc := range []struct {
		class string
		got   []manifestEntry
		want  []string
	}{
		{"checksums", m.Checksums, []string{"app_checksums.txt"}},
		{"sboms", m.SBOMs, []string{"app.tar.gz.sbom.json"}},
		{"provenance", m.Provenance, []string{"slsa-provenance.intoto.json"}},

		// Evidence is empty by design: doctor-*, trivy-* and image-sbom.* are
		// internal and must not reach the release page at all, so they are
		// dropped by the allowlist before classification rather than recorded
		// here.
		{"evidence", m.Evidence, nil},
	} {
		names := make([]string, 0, len(tc.got))
		for _, e := range tc.got {
			names = append(names, e.Name)
		}

		if !slices.Equal(names, tc.want) {
			t.Errorf("manifest %s = %v, want %v", tc.class, names, tc.want)
		}
	}
}

func TestReleaseFiles_ChecksumCrossChecksFailClosed(t *testing.T) {
	t.Parallel()

	root := releaseFilesFixture(t)
	manifest := "dist/forgejo-ci-release-files.json"

	if _, stderr, code := run(t, runOpts{dir: root},
		"release", "files", "collect", "--manifest", manifest, "--output", "assets.json"); code != 0 {
		t.Fatalf("collect exit %d\nstderr: %s", code, stderr)
	}

	// The cross-checks name the manifest, and a named manifest has to exist.
	if _, stderr, code := run(t, runOpts{dir: root},
		"release", "files", "manifest", "--manifest", manifest, "--assets-json", "assets.json"); code != 0 {
		t.Fatalf("manifest exit %d\nstderr: %s", code, stderr)
	}

	good := readFile(t, filepath.Join(root, "dist", "app_checksums.txt"))

	// A duplicated subject must be rejected: two lines claiming the same
	// file makes the signed checksum file ambiguous.
	first, _, _ := strings.Cut(good, "\n")
	dup := good + first + "\n"
	if err := os.WriteFile(filepath.Join(root, "dup_checksums.txt"), []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: root},
		"release", "files", "validate-checksums", "--manifest", manifest,
		"--checksums-file", "dup_checksums.txt")
	if code == 0 {
		t.Fatal("duplicate checksum subject must fail")
	}

	assertContains(t, "duplicate-subject rejection", stderr, "duplicate subjects")

	// A checksum line for a NON-public file must be rejected: the signed
	// checksum file must only vouch for published assets.
	nonpublic := good + sha256File(t, filepath.Join(root, "dist", "metadata.json")) + "  metadata.json\n"
	if err := os.WriteFile(filepath.Join(root, "nonpublic_checksums.txt"), []byte(nonpublic), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: root},
		"release", "files", "validate-checksums", "--manifest", manifest,
		"--checksums-file", "nonpublic_checksums.txt")
	if code == 0 {
		t.Fatal("non-public checksum subject must fail")
	}

	assertContains(t, "non-public-subject rejection", stderr, "not public release assets")

	// The two refusals the cross-check exists for, which neither case above
	// reaches: a recorded digest that does not match the bytes on disk, and a
	// public asset the checksum file does not vouch for at all.
	wrong := strings.Replace(good, sha256File(t, filepath.Join(root, "dist", "app.tar.gz")), strings.Repeat("0", 64), 1)
	if wrong == good {
		t.Fatal("fixture: the app.tar.gz digest was not found in the checksum file")
	}

	if err := os.WriteFile(filepath.Join(root, "wrong_checksums.txt"), []byte(wrong), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: root},
		"release", "files", "validate-checksums", "--manifest", manifest,
		"--checksums-file", "wrong_checksums.txt")
	if code != exitValidation {
		t.Fatalf("a wrong digest for app.tar.gz was accepted: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "digest-mismatch rejection", stderr, "checksum digest mismatch for app.tar.gz")

	partial := strings.Join(strings.Split(strings.TrimSpace(good), "\n")[1:], "\n") + "\n"
	if err := os.WriteFile(filepath.Join(root, "partial_checksums.txt"), []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: root},
		"release", "files", "validate-checksums", "--manifest", manifest,
		"--checksums-file", "partial_checksums.txt")
	if code != exitValidation {
		t.Fatalf("a checksum file missing a public asset was accepted: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "missing-asset rejection", stderr, "checksum file is missing public release assets")
	assertContains(t, "missing-asset rejection names it", stderr, "app.tar.gz")
}
