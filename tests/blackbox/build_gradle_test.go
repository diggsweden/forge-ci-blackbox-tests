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

	for line := range strings.SplitSeq(string(output), "\n") {
		home, found := strings.CutPrefix(strings.TrimSpace(line), "java.home = ")
		if !found {
			continue
		}
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("java.home is not absolute: %q: %w", home, os.ErrInvalid)
		}
		for _, name := range []string{"java", "javac"} {
			info, statErr := os.Stat(filepath.Join(home, "bin", name))
			if statErr != nil {
				return "", fmt.Errorf("JDK %s: %w", name, statErr)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return "", fmt.Errorf("JDK %s is not executable: %w", name, os.ErrInvalid)
			}
		}

		return home, nil
	}

	return "", fmt.Errorf("runtime did not report java.home: %w", os.ErrInvalid)
}

func TestJavaHome_RuntimeMetadataAndHealth(t *testing.T) {
	t.Parallel()

	for _, scenario := range []string{"launcher", "relative home", "missing property", "missing compiler", "failed runtime"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			home := filepath.Join(root, "real JDK", "Contents", "Home")
			if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"java", "javac"} {
				if name == "javac" && scenario == "missing compiler" {
					continue
				}
				if err := os.WriteFile(filepath.Join(home, "bin", name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			body := "#!/bin/sh\nprintf '    java.home = %s\\n' \"$REPORTED_HOME\" >&2\n"
			if scenario == "missing property" {
				body = "#!/bin/sh\nprintf 'java version fixture\\n' >&2\n"
			}
			if scenario == "failed runtime" {
				body += "exit 7\n"
			}
			launcher := filepath.Join(root, "launcher")
			if err := os.WriteFile(launcher, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			reported := home
			if scenario == "relative home" {
				reported = "relative/jdk"
			}
			got, err := inspectJavaHome(t.Context(), launcher, []string{"REPORTED_HOME=" + reported})
			if scenario != "launcher" {
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
