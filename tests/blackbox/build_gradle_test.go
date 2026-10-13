// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGradleSBOM_VersionLines verifies the build-layer SBOM across supported
// CycloneDX Gradle plugin lines. RenderGradleInitScript must use the artifact
// coordinate and class-based apply<CycloneDxPlugin>() accepted by each line.
//
// The optional local profile skips when the fixture lacks a gradlew; strict
// evidence fails because wrapper bootstrap would require unreviewed network I/O.
func TestGradleSBOM_VersionLines(t *testing.T) {
	requireTool(t, "java")

	proj := copyTree(t, fixture("gradle-hello"))

	if !fileExists(filepath.Join(proj, "gradlew")) {
		skipInOptionalProfilef(t, "gradlew not present in fixture (need a JDK + network to bootstrap)")
	}

	javaHome := detectJavaHome(t)

	// Plugin major versions write to different default locations; the
	// build-gradle workflow uploads both globs, so both are canon here.
	bomPathByVersion := map[string]string{
		"1.10.0": filepath.Join("build", "reports", "bom.json"),
		"2.0.0":  filepath.Join("build", "reports", "bom.json"),
		"3.2.1":  filepath.Join("build", "reports", "cyclonedx", "bom.json"),
	}

	for _, version := range []string{"1.10.0", "2.0.0", "3.2.1"} {
		t.Run("v"+version, func(t *testing.T) {
			// Clean per-version so the gradle cache doesn't mask a regression.
			for _, dir := range []string{".gradle", "build"} {
				if err := os.RemoveAll(filepath.Join(proj, dir)); err != nil {
					t.Fatal(err)
				}
			}

			_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{"JAVA_HOME": javaHome}},
				"build", "gradle", "run", "--tasks", "build", "--skip-tests", "--build-sbom", "--sbom-tool-version", version,
			)
			if code != 0 {
				t.Fatalf("gradle sbom v%s exit %d\nstderr:\n%s", version, code, stderr)
			}

			bom := filepath.Join(proj, bomPathByVersion[version])
			if !fileExists(bom) {
				t.Errorf("expected bom.json at %s", bom)

				return
			}

			// Parse it: a valid CycloneDX header proves the plugin ran
			// and wrote a real BOM, not a stub, at both plugin versions.
			assertValidCycloneDXJSON(t, bom)
		})
	}
}

// detectJavaHome resolves the active java's JAVA_HOME by resolving its
// absolute symlink target and walking up two directories. This works for both
// the system /usr/bin/java symlink and mise/asdf shims.
func detectJavaHome(t *testing.T) string {
	t.Helper()

	path := lookupTool("java")
	if path == "" {
		skipInOptionalProfilef(t, "java missing")
	}

	path, err := filepath.Abs(path)
	if err != nil {
		skipInOptionalProfilef(t, "resolve absolute java path: %v", err)
	}

	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		skipInOptionalProfilef(t, "resolve java symlinks: %v", err)
	}

	// .../bin/java → .../
	return filepath.Dir(filepath.Dir(path))
}
