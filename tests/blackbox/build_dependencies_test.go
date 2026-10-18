// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNPMBuildScopesCredentialsAcrossRealLifecyclePhases(t *testing.T) {
	requireTool(t, "npm")
	project := copyTree(t, fixture("npm-lib"))
	manifest := filepath.Join(project, "package.json")
	var pkg map[string]any
	if err := json.Unmarshal([]byte(readFile(t, manifest)), &pkg); err != nil {
		t.Fatal(err)
	}
	pkg["scripts"] = map[string]string{"preinstall": "node check-phase.cjs dependency", "build": "node check-phase.cjs build"}
	body, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(manifest, body, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	script := `const phase = process.argv[2];
for (const name of ['GH_TOKEN', 'CI_TOKEN', 'CI_REGISTRY_PASSWORD', 'GPG_PRIVATE_KEY']) {
  if (process.env[name]) throw new Error('unexpected credential: ' + name);
}
const expected = phase === 'dependency' ? 'synthetic-read-only' : undefined;
if (process.env.DEPENDENCY_TOKEN !== expected) throw new Error('wrong dependency credential scope');
console.log(phase + ' phase checked');
`
	if writeErr := os.WriteFile(filepath.Join(project, "check-phase.cjs"), []byte(script), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, stderr, code := runTool(t, project, "npm", "install", "--package-lock-only", "--ignore-scripts"); code != 0 {
		t.Fatalf("lockfile: %d: %s", code, stderr)
	}
	env := map[string]string{
		"DEPENDENCY_TOKEN": "synthetic-read-only", "ENABLE_BUILD_SBOM": "false",
		"GH_TOKEN": "synthetic-forge", "CI_TOKEN": "synthetic-ci", "CI_REGISTRY_PASSWORD": "synthetic-registry", "GPG_PRIVATE_KEY": "synthetic-signing",
	}
	stdout, stderr, code := run(t, runOpts{dir: project, env: env}, "build", "npm", "run", "--skip-tests", "--private-dependencies", "--dependency-registry", "https://registry.example/")
	if code != 0 {
		t.Fatalf("build: %d: %s", code, stderr)
	}
	for _, phase := range []string{"dependency", "build"} {
		if !strings.Contains(stdout+stderr, phase+" phase checked") {
			t.Fatalf("%s lifecycle was not observed: %s%s", phase, stdout, stderr)
		}
	}
}

func TestBuildPrivateDependenciesRefuseBeforeBuild(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		code       int
		diagnostic string
	}{
		{"npm registry", []string{"build", "npm", "run", "--private-dependencies", "--dependency-registry", "http://remote.example/"}, exitConfig, "HTTPS"},
		{"npm token", []string{"build", "npm", "run", "--private-dependencies", "--dependency-registry", "https://registry.example/"}, exitNoPerm, "DEPENDENCY_TOKEN"},
		{"maven settings", []string{"build", "maven", "run", "--build-type", "app", "--private-dependencies"}, exitConfig, "settings-path"},
		{"gradle token", []string{"build", "gradle", "run", "--tasks", "assemble", "--private-dependencies"}, exitNoPerm, "DEPENDENCY_TOKEN"},
		{"unsupported export validation flag", []string{"build", "gradle", "export-publications", "--version", "1.2.3", "--output", "publication", "--validate-dependencies-only"}, exitUsage, "validate-dependencies-only"},
		{"Central authorization", []string{"publish", "maven-central", "deploy", "--profile", "central-release"}, exitNoPerm, "release-request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, stderr, code := run(t, runOpts{dir: dir}, tc.args...)
			if code != tc.code || !strings.Contains(stderr, tc.diagnostic) {
				t.Fatalf("exit=%d, want %d and %q: %s", code, tc.code, tc.diagnostic, stderr)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("refused preflight changed the empty project: %v, %v", entries, err)
			}
		})
	}
}
