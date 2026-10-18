// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
)

// TestGoBuild_Reproducible verifies that `forge-ci build go compile`
// produces byte-identical binaries across runs when SOURCE_DATE_EPOCH
// is fixed. Reproducible builds let a SHA256 stand in as a true
// fingerprint of the inputs.
//
// We also assert that a DIFFERENT SOURCE_DATE_EPOCH yields a different
// SHA — otherwise the date isn't actually being baked in (silent
// failure mode of an ldflag injection).
func TestGoBuild_Reproducible(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")

	compile := func(epoch string) string {
		proj := copyTree(t, fixture("go-hello"))
		env := map[string]string{"SOURCE_DATE_EPOCH": epoch, "GITHUB_SHA": "abc123", "GOCACHE": t.TempDir()}
		_, _, code := run(t, runOpts{dir: proj, env: env},
			"build", "go", "run",
			"--version", "v0.1.0", "--platforms", "linux/amd64",
		)
		if code != 0 {
			t.Fatalf("compile exit %d", code)
		}

		return sha256File(t, filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64"))
	}

	first := compile("1700000000")
	second := compile("1700000000")

	if first != second {
		t.Errorf("two compiles with identical inputs produced different SHAs:\n  first:  %s\n  second: %s", first, second)
	}

	// Change SOURCE_DATE_EPOCH; SHA must change.
	third := compile("1800000000")
	if third == first {
		t.Errorf("changing SOURCE_DATE_EPOCH did not change binary SHA — date is not being baked in")
	}
}

// TestGoBuild_MultiPlatformReproducible verifies reproducibility holds
// across every platform a release matrix would emit (linux/amd64,
// darwin/arm64, windows/amd64). The .exe suffix on windows is handled
// transparently.
func TestGoBuild_MultiPlatformReproducible(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")

	platforms := "linux/amd64,darwin/arm64,windows/amd64"
	files := map[string]string{
		"linux/amd64":   filepath.Join("dist", "linux-amd64", "go-hello-linux-amd64"),
		"darwin/arm64":  filepath.Join("dist", "darwin-arm64", "go-hello-darwin-arm64"),
		"windows/amd64": filepath.Join("dist", "windows-amd64", "go-hello-windows-amd64.exe"),
	}

	compile := func() map[string]string {
		proj := copyTree(t, fixture("go-hello"))
		env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000", "GITHUB_SHA": "abc123", "GOCACHE": t.TempDir()}
		_, _, code := run(t, runOpts{dir: proj, env: env},
			"build", "go", "run", "--version", "v0.1.0", "--platforms", platforms,
		)
		if code != 0 {
			t.Fatalf("compile exit %d", code)
		}

		hashes := make(map[string]string, len(files))
		for k, p := range files {
			hashes[k] = sha256File(t, filepath.Join(proj, p))
		}

		return hashes
	}

	first := compile()

	second := compile()
	for plat, hash := range first {
		if second[plat] != hash {
			t.Errorf("platform %s not reproducible:\n  first:  %s\n  second: %s", plat, hash, second[plat])
		}
	}

	// The control this test needs to mean anything about *multi-platform*
	// building: comparing each platform only against itself passes just as
	// well if the cross-compile ignored GOOS/GOARCH and emitted one binary
	// three times. TestGoBuild_Reproducible makes the same move with
	// SOURCE_DATE_EPOCH; the matrix needs its own.
	distinct := make(map[string]string, len(first))
	for plat, hash := range first {
		if other, clash := distinct[hash]; clash {
			t.Errorf("%s and %s produced byte-identical binaries (%s) — the target was not applied",
				plat, other, hash)
		}

		distinct[hash] = plat
	}
}

// TestGoSBOM_CISABuildLayer verifies the CISA "build" layer SBOM
// for a Go project via cyclonedx-gomod. The generator writes a
// CycloneDX JSON document under .forge-ci/go-build-sbom/<name>/
// with components derived from go.mod.
func TestGoSBOM_CISABuildLayer(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")
	requireTool(t, "cyclonedx-gomod")

	proj := copyTree(t, fixture("go-hello"))

	// copyTree copies the fixture verbatim, so "the file exists afterwards" is
	// only evidence of generation if it was absent beforehand. Assert that,
	// rather than trusting the fixture to stay clean.
	bomPath := filepath.Join(proj, ".forge-ci", "go-build-sbom", "go-hello", "bom.json")
	if fileExists(bomPath) {
		t.Fatalf("fixture go-hello ships %s; the generation assertion below cannot fail while it does",
			filepath.Join(".forge-ci", "go-build-sbom", "go-hello", "bom.json"))
	}

	_, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "build", "--project-type", "go", "--name", "go-hello")
	if code != 0 {
		t.Fatalf("sbom exit %d\nstderr: %s", code, stderr)
	}

	assertValidCycloneDXJSON(t, bomPath)

	var bom struct {
		Components []any `json:"components"`
	}
	decodeJSON(t, bomPath, readFile(t, bomPath), &bom)

	if len(bom.Components) == 0 {
		t.Errorf("no components — go.mod has cobra dep, so the SBOM should list it")
	}
}

// TestGoSBOM_AnalyzedArtifact verifies the CISA "analyzed-artifact"
// layer for Go via syft. After compile, syft analyses the resulting
// binary and emits BOTH SPDX 2.3 and CycloneDX 1.6 documents.
func TestGoSBOM_AnalyzedArtifact(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")
	requireTool(t, "syft")

	proj := copyTree(t, fixture("go-hello"))

	_, _, code := run(t, runOpts{dir: proj, env: map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}},
		"build", "go", "run", "--version", "v0.1.0", "--platforms", "linux/amd64",
	)
	if code != 0 {
		t.Fatalf("compile exit %d", code)
	}

	_, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--layers", "analyzed-artifact",
		"--version", "0.1.0",
		"--name", "go-hello",
	)
	if code != 0 {
		t.Fatalf("sbom exit %d\nstderr: %s", code, stderr)
	}

	spdxPath := filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.spdx.json")
	cdxPath := filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.cyclonedx.json")

	assertValidSPDXJSON(t, spdxPath)
	assertValidCycloneDXJSON(t, cdxPath)

	var spdx struct {
		Name     string `json:"name"`
		Packages []any  `json:"packages"`
	}
	decodeJSON(t, spdxPath, readFile(t, spdxPath), &spdx)

	if spdx.Name == "" {
		t.Errorf("SPDX document name empty")
	}

	if len(spdx.Packages) == 0 {
		t.Errorf("SPDX has no packages")
	}

	var cdx struct {
		Components []any `json:"components"`
	}
	decodeJSON(t, cdxPath, readFile(t, cdxPath), &cdx)

	if len(cdx.Components) == 0 {
		t.Errorf("CycloneDX has no components")
	}
}
