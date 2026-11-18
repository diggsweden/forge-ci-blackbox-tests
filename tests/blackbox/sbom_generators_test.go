// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestSBOMBuild_ReviewedGenerators runs the reviewed generator versions through
// the real build commands. An argv-only test cannot detect a changed upstream
// option or a generator that no longer describes the project it was given.
func TestSBOMBuild_ReviewedGenerators(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, fixture, generator, name, version, bom string
	}{
		{"npm", "npm-lib", "6.0.0", "npm-lib", "0.1.0", "bom.json"},
		{"maven", "maven-hello", "2.9.3", "maven-hello", "1.0.0", "target/bom.json"},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			tool := "npm"
			if tc.ecosystem == "maven" {
				tool = "mvn"
			}
			requireTool(t, tool)
			proj := copyTree(t, fixture(tc.fixture))
			if tc.ecosystem == "npm" {
				if _, stderr, code := runTool(t, proj, "npm", "install", "--package-lock-only", "--ignore-scripts"); code != 0 {
					t.Fatalf("prepare npm lockfile: exit %d: %s", code, stderr)
				}
			}
			args := []string{"build", tc.ecosystem, "run", "--sbom-tool-version", tc.generator}
			if tc.ecosystem == "maven" {
				args = append(args, "--build-type", "app", "--maven-cli-opts", "-B -ntp")
			}
			if _, stderr, code := run(t, runOpts{dir: proj}, args...); code != 0 {
				t.Fatalf("build with generator %s: exit %d: %s", tc.generator, code, stderr)
			}
			path := filepath.Join(proj, tc.bom)
			assertValidCycloneDXJSON(t, path)
			var bom struct {
				Metadata struct {
					Component struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"component"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal([]byte(readFile(t, path)), &bom); err != nil {
				t.Fatal(err)
			}
			if bom.Metadata.Component.Name != tc.name || bom.Metadata.Component.Version != tc.version {
				t.Fatalf("SBOM describes %+v, want %s@%s", bom.Metadata.Component, tc.name, tc.version)
			}
		})
	}
}

// TestSBOMBuild_LockfileLayer runs `sbom build` for the two ecosystems whose
// build-layer SBOM forge-ci generates from the lockfile, and asserts a
// CycloneDX document describing the project lands where `sbom assemble`
// harvests it. Go, whose go.mod requires cobra, must also list components.
func TestSBOMBuild_LockfileLayer(t *testing.T) {
	for _, tc := range []struct {
		projectType, fixture, generator, bom, subject string
		probe                                         []string
		dependencies                                  bool
	}{
		{"go", "go-hello", "cyclonedx-gomod", ".forge-ci/go-build-sbom/go-hello/bom.json", "github.com/example/go-hello", []string{"go", "version"}, true},
		{"cargo", "cargo-hello", "cargo-cyclonedx", "bom.json", "cargo-hello", []string{"cargo", "--version"}, false},
	} {
		t.Run(tc.projectType, func(t *testing.T) {
			requireWorkingTool(t, tc.probe[0], tc.probe[1:]...)
			requireTool(t, tc.generator)

			proj := copyTree(t, fixture(tc.fixture))

			// Existence afterwards is evidence of generation only if the file
			// was absent before.
			bomPath := filepath.Join(proj, tc.bom)
			if fileExists(bomPath) {
				t.Fatalf("fixture %s ships %s; the generation assertion cannot fail while it does", tc.fixture, tc.bom)
			}

			if _, stderr, code := run(t, runOpts{dir: proj},
				"sbom", "build", "--project-type", tc.projectType, "--name", tc.fixture); code != 0 {
				t.Fatalf("sbom build exit %d\nstderr: %s", code, stderr)
			}

			assertValidCycloneDXJSON(t, bomPath)
			assertSBOMSubject(t, bomPath, tc.subject)

			var bom struct {
				Components []any `json:"components"`
			}
			decodeJSON(t, bomPath, readFile(t, bomPath), &bom)

			if tc.dependencies && len(bom.Components) == 0 {
				t.Errorf("%s lists no components, but the fixture has dependencies", tc.bom)
			}
		})
	}
}
