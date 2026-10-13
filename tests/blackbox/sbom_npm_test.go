// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// NPM-specific integration tests: the analyzed-artifact SBOM flow,
// build-type-specific assertions (application vs pack/lib) live in
// build_type_test.go.
//
// Cross-cutting NPM coverage (version bump, reproducibility, exit
// codes) is in the matrix files (version_bump_matrix_test.go,
// reproducibility_test.go, cli_exit_codes_test.go).

package blackbox

import (
	"path/filepath"
	"testing"
)

// TestSBOMNPM_AnalyzedArtifactEmitsBothFormats verifies the CISA analyzed-artifact
// layer for an NPM project: `npm pack` produces a tarball, then
// `sbom assemble --layers=analyzed-artifact` runs syft against
// it and emits both SPDX and CycloneDX documents.
//
// Skips when `npm` is not on PATH. The matrix test
// TestSBOMAnalyzedArtifact_BothFormatsAcrossEcosystems covers jar/binary variants
// with stubbed artifacts; this test exercises the NPM-specific path
// with a real tarball.
func TestSBOMNPM_AnalyzedArtifactEmitsBothFormats(t *testing.T) {
	requireTool(t, "syft")
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-lib"))

	if _, _, code := runTool(t, proj, "npm", "pack"); code != 0 {
		t.Fatalf("npm pack failed")
	}

	_, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "npm",
		"--layers", "analyzed-artifact",
		"--version", "0.1.0",
		"--name", "npm-lib")
	if code != 0 {
		t.Fatalf("sbom assemble exit %d", code)
	}

	// The analyzed layer must emit BOTH an SPDX and a CycloneDX
	// document, and each must parse as a real BOM of its format — not
	// merely exist. Glob rather than hard-code the basename so the
	// git-SHA-injected variant of the name still matches.
	spdx := globOne(t, proj, "*analyzed*sbom*.spdx.json")
	assertValidSPDXJSON(t, spdx)

	cdx := globOne(t, proj, "*analyzed*sbom*.cyclonedx.json")
	assertValidCycloneDXJSON(t, cdx)

	// …and that both describe THIS tarball. Format validity says the document
	// is well-formed, not what it is a document of: an SBOM generated against
	// a stale artifact left in the working directory would satisfy every check
	// above while making a false claim about what shipped.
	//
	// The cargo tests already assert this via assertCycloneDXXMLComponent; the
	// JSON layers had no equivalent until assertSBOMSubject.
	//
	// This test deliberately does not assert a non-empty component list. `npm
	// pack` excludes lockfiles from tarballs, and syft enumerates JavaScript
	// dependencies from package-lock.json or node_modules, neither of which is
	// in a published tarball. The analyzed-artifact SBOM of an npm tarball
	// reports zero CycloneDX components and one SPDX package (the tarball
	// itself).
	//
	// The dependency list for npm comes from the BUILD layer instead, which is
	// generated from the lockfile by the ecosystem tool and promoted by
	// `sbom assemble --layers build` (see sbom_matrix_test.go). Requiring
	// components here would be a false failure on correct output.
	tarball := filepath.Base(globOne(t, proj, "*.tgz"))
	assertSBOMSubject(t, spdx, tarball)
	assertSBOMSubject(t, cdx, tarball)
}

// globOne returns the single file under dir matching pattern, failing
// the test when zero or more than one match (an ambiguous or missing
// artifact is a real defect, not something to paper over).
func globOne(t *testing.T, dir, pattern string) string {
	t.Helper()

	matches := globMust(dir, pattern)

	if len(matches) != 1 {
		t.Fatalf("glob %s: want exactly 1 match, got %d: %v", pattern, len(matches), matches)
	}

	return matches[0]
}
