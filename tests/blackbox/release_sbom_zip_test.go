// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `release sbom-zip` bundles every SBOM layer the release produced
// into <project>-<version>-sboms.zip, with the option to GPG-sign the
// resulting zip. This is the file that attaches to the GitHub Release.
//
// Per-ecosystem SBOM generation (build layer + analyzed-artifact)
// lives in sbom_matrix_test.go and the per-ecosystem files.

package blackbox

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestSBOMZip_BundlesLayersClosedSet verifies that `release sbom-zip` discovers
// every SBOM under the working dir, plus analyzed-container SBOMs
// under --sbom-dir, and bundles them into <project>-<version>-sboms.zip.
func TestSBOMZip_BundlesLayersClosedSet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Each SBOM body carries a distinct marker. The bundle is checked by
	// CONTENT below, not just by entry name, and identical bodies would make
	// a bundler that copied one layer three times indistinguishable from one
	// that copied three.
	files := map[string]string{
		"app-1.0.0-sbom.spdx.json":              `{"spdxVersion":"SPDX-2.3","name":"build-layer"}`,
		"app-1.0.0-sbom.cyclonedx.json":         `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:cdx"}`,
		"app-1.0.0-analyzed-jar-sbom.spdx.json": `{"spdxVersion":"SPDX-2.3","name":"analyzed-jar"}`,
		// Decoy: not an SBOM. Must NOT be swept into the bundle.
		"not-an-sbom.txt": "plain file",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	containerDir := filepath.Join(dir, "sbom-artifacts")
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		t.Fatal(err)
	}

	containerSBOM := filepath.Join(containerDir, "app-1.0.0-analyzed-container-sbom.spdx.json")

	const containerBody = `{"spdxVersion":"SPDX-2.3","name":"analyzed-container"}`

	if err := os.WriteFile(containerSBOM, []byte(containerBody), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{dir: dir},
		"release", "sbom-zip",
		"--project-name", "app",
		"--version", "1.0.0",
		"--sbom-dir", "sbom-artifacts")
	if code != 0 {
		t.Fatalf("release sbom-zip exit %d", code)
	}

	zipPath := filepath.Join(dir, "app-1.0.0-sboms.zip")
	if !fileExists(zipPath) {
		t.Fatalf("expected %s", zipPath)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}

	defer func() { _ = zr.Close() }()

	got := map[string]string{}

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, err)
		}

		body, err := io.ReadAll(rc)
		_ = rc.Close()

		if err != nil {
			t.Fatalf("read zip entry %s: %v", f.Name, err)
		}

		got[f.Name] = string(body)
	}

	want := []string{
		"app-1.0.0-sbom.spdx.json",
		"app-1.0.0-sbom.cyclonedx.json",
		"app-1.0.0-analyzed-jar-sbom.spdx.json",
		// Container SBOMs are flattened (no sbom-artifacts/ prefix).
		"app-1.0.0-analyzed-container-sbom.spdx.json",
	}
	for _, name := range want {
		body, ok := got[name]
		if !ok {
			t.Errorf("zip missing %s; entries: %v", name, sortedKeys(got))

			continue
		}

		// By CONTENT, not just by name. This zip attaches to the release page
		// and is what a consumer downloads to audit the release, so an entry
		// present but empty — or carrying a different layer's document — is
		// the failure that matters. Name-only checks pass all of those.
		wantBody := files[name]
		if name == "app-1.0.0-analyzed-container-sbom.spdx.json" {
			wantBody = containerBody
		}

		if body != wantBody {
			t.Errorf("zip entry %s content = %q, want %q", name, body, wantBody)
		}
	}

	// Closed set: this zip attaches to the release page, so sweeping in
	// anything beyond the SBOM layers (the decoy above, say) ships it.
	if len(zr.File) != len(want) {
		t.Errorf("zip has %d entries, want exactly %d: %v", len(zr.File), len(want), sortedKeys(got))
	}
}

// TestSBOMZip_SignedWithGPG verifies the --sign path: an .asc detached
// signature must land next to the zip and verify against the same key.
func TestSBOMZip_SignedWithGPG(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "x-1.0.0-sbom.spdx.json"),
		[]byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{
		dir: dir,
		env: key.signingEnv(t),
	},
		"release", "sbom-zip",
		"--project-name", "x",
		"--version", "1.0.0",
		"--sign")
	if code != 0 {
		t.Fatalf("release sbom-zip exit %d", code)
	}

	zipPath := filepath.Join(dir, "x-1.0.0-sboms.zip")
	sigPath := zipPath + ".asc"

	for _, p := range []string{zipPath, sigPath} {
		if !fileExists(p) {
			t.Fatalf("expected %s", p)
		}
	}

	// The comment above promises verification, so verify: the detached
	// signature must check out against the only key in the keyring.
	cmd := toolCommand(t, dir, map[string]string{"GNUPGHOME": key.gnupgHome},
		"gpg", "--verify", sigPath, zipPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("gpg --verify failed: %v\n%s", err, out)
	}
}
