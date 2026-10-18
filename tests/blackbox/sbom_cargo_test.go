// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
)

// TestCargoSBOM_SingleCrate verifies cargo-cyclonedx produces a per-crate
// bom.xml. forge-ci doesn't run cargo here — the SBOM is generated
// by the upstream tool and consumed by sbom-cargo.yml at workflow
// level. This test confirms the contract is honoured.
func TestCargoSBOM_SingleCrate(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")

	proj := copyTree(t, fixture("cargo-hello"))

	cmd := toolCommand(t, proj, nil, "cargo", "cyclonedx", "--override-filename", "bom")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo cyclonedx: %v\n%s", err, out)
	}

	// A present file isn't enough: parse it and confirm it is a real
	// CycloneDX XML BOM naming this crate, so an empty or truncated
	// bom.xml would fail the test.
	assertCycloneDXXMLComponent(t, filepath.Join(proj, "bom.xml"), "cargo-hello")
}

// TestCargoSBOM_WorkspaceEmitsPerMemberBOMs verifies the workspace variant produces one
// bom.xml per workspace member (not one merged file).
func TestCargoSBOM_WorkspaceEmitsPerMemberBOMs(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")

	proj := copyTree(t, fixture("cargo-workspace"))

	cmd := toolCommand(t, proj, nil, "cargo", "cyclonedx", "--override-filename", "bom")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo cyclonedx: %v\n%s", err, out)
	}

	for _, crate := range []string{"common", "cli", "server"} {
		bom := filepath.Join(proj, "crates", crate, "bom.xml")
		if !fileExists(bom) {
			t.Errorf("expected bom.xml at %s", bom)

			continue
		}

		// Each member's BOM must name that member, proving they are
		// per-crate documents rather than three copies of one merged BOM.
		assertCycloneDXXMLComponent(t, bom, crate)
	}
}
