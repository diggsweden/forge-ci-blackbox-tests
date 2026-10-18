// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stubCycloneDXBOM returns a minimal but schema-valid CycloneDX 1.6
// document body. The CISA build-layer "generator" is really a
// promote-and-rename — the source bom.json is produced by the
// ecosystem-native tool (cyclonedx-maven-plugin, cyclonedx-gomod,
// cargo-cyclonedx, …) during the project's own build. forge-ci's
// job is only to discover and copy it under the canonical layer
// filename. Stubbing lets the test cover that contract without
// invoking the (often slow) generator.
func stubCycloneDXBOM() []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"serialNumber":"` + stubBOMSerial + `","components":[{"type":"library","name":"` + stubBOMComponent + `","version":"9.9.9"}]}`)
}

// The stub carries marks that identify it. Promotion is a copy, so they must
// survive it — and only a copy produces them. Asserting a valid CycloneDX
// header instead would pass just as well if the verb ignored the source file
// and generated a fresh document, which is the one thing this layer must not
// do: the build layer's dependency list comes from the ecosystem-native tool,
// and forge-ci's whole role here is to discover and rename it.
const (
	stubBOMSerial    = "urn:uuid:5b1e7c3a-0000-4000-8000-0000000000ff"
	stubBOMComponent = "stub-upstream-component"
)

// minimalZip returns an empty zip archive: just the 22-byte "end of central
// directory" record, which a permissive scanner (syft) accepts.
func minimalZip() []byte {
	var archive bytes.Buffer
	if err := zip.NewWriter(&archive).Close(); err != nil {
		panic("blackbox: cannot build empty zip: " + err.Error())
	}

	return archive.Bytes()
}

// TestSBOMBuildLayer_PromotesAcrossEcosystems verifies the CISA Build layer for
// every supported ecosystem. The Build layer is the dependency-list
// SBOM produced by the upstream tool — forge-ci's role is to
// discover and promote it to the canonical filename. The test stubs
// the upstream output and asserts the promotion.
func TestSBOMBuildLayer_PromotesAcrossEcosystems(t *testing.T) {
	cases := []struct {
		name        string
		fixture     string
		projectType string
		// path under the fixture where the upstream tool would drop bom.json
		bomPath string
	}{
		{name: "maven", fixture: "maven-hello", projectType: "maven", bomPath: "target/bom.json"},
		{name: "npm", fixture: "npm-lib", projectType: "npm", bomPath: "bom.json"},
		{name: "gradle", fixture: "gradle-hello", projectType: "gradle", bomPath: "build/reports/bom.json"},
		{name: "cargo", fixture: "cargo-hello", projectType: "cargo", bomPath: "bom.json"},
		{name: "go", fixture: "go-hello", projectType: "go", bomPath: "bom.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proj := copyTree(t, fixture(tc.fixture))

			dst := filepath.Join(proj, tc.bomPath)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(dst, stubCycloneDXBOM(), 0o600); err != nil {
				t.Fatal(err)
			}

			_, stderr, code := run(t, runOpts{dir: proj},
				"sbom", "assemble",
				"--project-type", tc.projectType,
				"--layers", "build",
				"--name", tc.fixture,
				"--version", "1.0.0",
			)
			if code != 0 {
				t.Fatalf("sbom generate all exit %d\nstderr: %s", code, stderr)
			}

			out := filepath.Join(proj, tc.fixture+"-1.0.0-build-sbom.cyclonedx.json")
			if !fileExists(out) {
				t.Fatalf("expected build SBOM at %s", out)
			}

			// Promoted SBOM must remain a valid CycloneDX document…
			var doc struct {
				BomFormat    string `json:"bomFormat"`
				SpecVersion  string `json:"specVersion"`
				SerialNumber string `json:"serialNumber"`
				Components   []struct {
					Name string `json:"name"`
				} `json:"components"`
			}
			if err := json.Unmarshal([]byte(readFile(t, out)), &doc); err != nil {
				t.Fatalf("parse promoted SBOM: %v", err)
			}

			if doc.BomFormat != "CycloneDX" || !strings.HasPrefix(doc.SpecVersion, "1.") {
				t.Errorf("CycloneDX header wrong in promoted SBOM: %+v", doc)
			}

			// …and it must be THE UPSTREAM DOCUMENT, not a fresh one that
			// merely looks like it. The serial number and component come from
			// the stub, so a verb that regenerated instead of promoting would
			// emit a valid CycloneDX file with neither.
			if doc.SerialNumber != stubBOMSerial {
				t.Errorf("promoted SBOM serialNumber = %q, want the upstream %q — the build layer regenerated instead of promoting",
					doc.SerialNumber, stubBOMSerial)
			}

			names := make([]string, 0, len(doc.Components))
			for _, c := range doc.Components {
				names = append(names, c.Name)
			}

			if !slices.Contains(names, stubBOMComponent) {
				t.Errorf("promoted SBOM components = %v, want the upstream %q — the dependency list did not survive promotion",
					names, stubBOMComponent)
			}
		})
	}
}

// TestSBOMAnalyzedArtifact_BothFormatsAcrossEcosystems verifies the CISA
// analyzed-artifact layer for every ecosystem with a binary artifact
// type. Each case materialises a stub artifact in the location
// `findXxx()` (see internal/app/sbom/discovery.go) expects, runs
// `sbom generate all --layers=analyzed-artifact`, and asserts that
// BOTH SPDX 2.3 and CycloneDX SBOMs are produced.
//
// Stubbing instead of "build the real thing": syft accepts minimal
// archives + executables, so a 22-byte empty zip / two-line shell
// script is enough to exercise the syft-invocation pipeline and the
// forge-ci wrapper logic.
func TestSBOMAnalyzedArtifact_BothFormatsAcrossEcosystems(t *testing.T) {
	requireTool(t, "syft")

	cases := []struct {
		name        string
		fixture     string
		projectType string
		// artifact path under the fixture and content kind
		artifactPath string
		artifactBody []byte
		// expected SBOM filenames (suffix; we match against the basename)
		expectSPDX string
		expectCDX  string
		// optional: must be executable
		makeExecutable bool
	}{
		{
			name:         "maven_jar",
			fixture:      "maven-hello",
			projectType:  "maven",
			artifactPath: "target/maven-hello-1.0.0.jar",
			artifactBody: minimalZip(),
			expectSPDX:   "maven-hello-1.0.0-analyzed-jar-sbom.spdx.json",
			expectCDX:    "maven-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json",
		},
		{
			name:         "gradle_jar",
			fixture:      "gradle-hello",
			projectType:  "gradle",
			artifactPath: "build/libs/gradle-hello-1.0.0.jar",
			artifactBody: minimalZip(),
			expectSPDX:   "gradle-hello-1.0.0-analyzed-jar-sbom.spdx.json",
			expectCDX:    "gradle-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json",
		},
		{
			name:           "cargo_binary",
			fixture:        "cargo-hello",
			projectType:    "cargo",
			artifactPath:   "target/release/cargo-hello",
			artifactBody:   []byte("#!/bin/sh\necho hi\n"),
			expectSPDX:     "cargo-hello-analyzed-binary-sbom.spdx.json",
			expectCDX:      "cargo-hello-analyzed-binary-sbom.cyclonedx.json",
			makeExecutable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proj := copyTree(t, fixture(tc.fixture))

			art := filepath.Join(proj, tc.artifactPath)
			if err := os.MkdirAll(filepath.Dir(art), 0o755); err != nil {
				t.Fatal(err)
			}

			mode := os.FileMode(0o600)
			if tc.makeExecutable {
				mode = 0o755
			}

			if err := os.WriteFile(art, tc.artifactBody, mode); err != nil {
				t.Fatal(err)
			}

			_, stderr, code := run(t, runOpts{dir: proj},
				"sbom", "assemble",
				"--project-type", tc.projectType,
				"--layers", "analyzed-artifact",
				"--name", tc.fixture,
				"--version", "1.0.0",
			)
			if code != 0 {
				t.Fatalf("sbom generate all exit %d\nstderr: %s", code, stderr)
			}

			spdx := filepath.Join(proj, tc.expectSPDX)
			cdx := filepath.Join(proj, tc.expectCDX)

			if !fileExists(spdx) {
				t.Errorf("missing SPDX SBOM at %s", spdx)
			}

			if !fileExists(cdx) {
				t.Errorf("missing CycloneDX SBOM at %s", cdx)
			}

			if fileExists(spdx) {
				assertValidSPDXJSON(t, spdx)

				// The generator pins the exact 2.3 revision, stricter than the
				// shared SPDX-2.x gate.
				var doc struct {
					SPDXVersion string `json:"spdxVersion"`
				}
				decodeJSON(t, "SPDX", readFile(t, spdx), &doc)

				if doc.SPDXVersion != "SPDX-2.3" {
					t.Errorf("SPDX version = %q, want SPDX-2.3", doc.SPDXVersion)
				}
			}

			if fileExists(cdx) {
				assertValidCycloneDXJSON(t, cdx)
			}
		})
	}
}

// TestSBOMBuildLayer_MissingBOMFails verifies the negative path: when
// no bom.json exists, `sbom generate all --layers=build` exits with
// a non-zero validation code rather than silently producing nothing.
// This is the regression that turned "no SBOMs generated" from a
// silent exit-0 into an explicit error.
func TestSBOMBuildLayer_MissingBOMFails(t *testing.T) {
	proj := copyTree(t, fixture("maven-hello"))

	_, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "maven",
		"--layers", "build",
		"--name", "maven-hello",
		"--version", "1.0.0",
	)
	if code != exitNoInput {
		t.Errorf("no bom.json source: exit %d, want 66 (EX_NOINPUT) — the upstream tool's output is a missing INPUT, not an internal fault\nstderr: %s", code, stderr)
	}

	// The message has to name the tool that produces the missing file: an
	// operator who has never run cyclonedx-maven-plugin cannot act on "not
	// found" alone.
	assertContains(t, "missing build SBOM", stderr, "no Maven Build SBOM found")
	assertContains(t, "missing build SBOM", stderr, "cyclonedx-maven-plugin")
}
