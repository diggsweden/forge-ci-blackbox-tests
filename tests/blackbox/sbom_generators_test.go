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
			args := []string{"build", tc.ecosystem, "run", "--skip-tests", "--sbom-tool-version", tc.generator}
			if tc.ecosystem == "maven" {
				args = append(args, "--build-type", "app", "--cli-opts", "-B -ntp")
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
