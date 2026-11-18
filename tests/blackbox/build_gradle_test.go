// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	proj := copyGradleFixture(t, "gradle-hello")

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
				"build", "gradle", "run", "--tasks", "build", "--build-sbom", "--sbom-tool-version", version,
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

// detectJavaHome asks the selected runtime rather than guessing from the
// executable's parent. Launchers such as macOS /usr/bin/java are not JDK paths.
func detectJavaHome(t *testing.T) string {
	t.Helper()

	path := lookupTool("java")
	if path == "" {
		skipInOptionalProfilef(t, "java missing")
	}

	home, err := inspectJavaHome(t.Context(), path, isolatedEnv(nil))
	if err != nil {
		t.Fatalf("Java runtime is not a usable JDK; run mise exec -- just install-dev-tools: %v", err)
	}

	return home
}

func inspectJavaHome(ctx context.Context, java string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, toolInspectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, java, "-XshowSettings:properties", "-version")
	cmd.Env = env
	killGroupOnCancel(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query java.home: %w: %s", err, output)
	}

	home, err := parseJavaHome(string(output))
	if err != nil {
		return "", err
	}

	return home, checkJDK(home)
}

// parseJavaHome returns the java.home that -XshowSettings:properties reports.
func parseJavaHome(output string) (string, error) {
	for line := range strings.SplitSeq(output, "\n") {
		home, found := strings.CutPrefix(strings.TrimSpace(line), "java.home = ")
		if !found {
			continue
		}
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("java.home is not absolute: %q: %w", home, os.ErrInvalid)
		}

		return home, nil
	}

	return "", fmt.Errorf("runtime did not report java.home: %w", os.ErrInvalid)
}

// checkJDK requires the executable java and javac a JDK home carries.
func checkJDK(home string) error {
	for _, name := range []string{"java", "javac"} {
		info, err := os.Stat(filepath.Join(home, "bin", name))
		if err != nil {
			return fmt.Errorf("JDK %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("JDK %s is not executable: %w", name, os.ErrInvalid)
		}
	}

	return nil
}

// The java and javac in these homes are only inspected, never run, so they
// are empty files with the executable bit.
func TestJavaHome_RuntimeMetadataAndHealth(t *testing.T) {
	t.Parallel()

	for _, scenario := range []string{"usable JDK", "relative home", "missing property", "missing compiler", "not executable"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			home := filepath.Join(t.TempDir(), "real JDK", "Contents", "Home")
			if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"java", "javac"} {
				if name == "javac" && scenario == "missing compiler" {
					continue
				}
				mode := os.FileMode(0o700)
				if name == "javac" && scenario == "not executable" {
					mode = 0o600
				}
				if err := os.WriteFile(filepath.Join(home, "bin", name), nil, mode); err != nil {
					t.Fatal(err)
				}
			}
			reported := home
			if scenario == "relative home" {
				reported = "relative/jdk"
			}
			output := "Property settings:\n    java.home = " + reported + "\n"
			if scenario == "missing property" {
				output = "java version fixture\n"
			}
			got, err := parseJavaHome(output)
			if err == nil {
				err = checkJDK(got)
			}
			if scenario != "usable JDK" {
				if err == nil {
					t.Fatalf("unusable JDK was accepted: %q", got)
				}

				return
			}
			if err != nil || got != home {
				t.Fatalf("runtime home = %q, %v; want reported JDK %q", got, err, home)
			}
		})
	}
}
