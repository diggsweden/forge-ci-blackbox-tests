// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGradlePublicationPreflightBeforeWrapperPreparation(t *testing.T) {
	project := t.TempDir()
	wrapper := filepath.Join(project, "gradlew")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexit 99\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: project}, "build", "gradle", "export-publications", "--version", "1.2.3", "--output", "publication", "--validate-only")
	if code != 0 {
		t.Fatalf("preflight must accept a wrapper before the build makes it executable: %d: %s", code, stderr)
	}

	info, err := os.Stat(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("preflight changed wrapper permissions: %v", info.Mode())
	}
	entries, err := os.ReadDir(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "gradlew" {
		t.Fatalf("preflight changed project files: %v", entries)
	}
}

func TestGradlePublicationMultiProjectBoundaries(t *testing.T) {
	requireTool(t, "java")
	for _, tc := range []struct{ name, override, diagnostic string }{
		{"two publications", "", ""},
		{"duplicate coordinates", "publishing.publications.library.artifactId = 'alpha'", "Duplicate Maven publication coordinates"},
		{"mixed versions", "publishing.publications.library.version = '2.2.0'", "Every publication must have the prepared release version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := copyGradleFixture(t, "gradle-multi-library")
			if tc.override != "" {
				if err := os.WriteFile(filepath.Join(project, "beta", "build.gradle"), []byte(tc.override), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(t.TempDir(), "publication")
			_, stderr, code := run(t, runOpts{dir: project, env: map[string]string{"JAVA_HOME": detectJavaHome(t)}}, "build", "gradle", "export-publications", "--version", "2.1.0", "--output", out)
			if tc.diagnostic != "" {
				if code == 0 || !strings.Contains(stderr, tc.diagnostic) {
					t.Fatalf("expected refusal %q, got %d: %s", tc.diagnostic, code, stderr)
				}
				// ArtifactStaging creates the destination root up front; a
				// refusal must remove all staging data and install no files.
				entries, readErr := os.ReadDir(out)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("failed export left files or unreadable output: %v, %v", entries, readErr)
				}

				return
			}
			if code != 0 {
				t.Fatalf("export: %d: %s", code, stderr)
			}
			for _, module := range []string{"alpha", "beta"} {
				pom := filepath.Join(out, "org/example/fixture", module, "2.1.0", module+"-2.1.0.pom")
				if !fileExists(pom) {
					t.Errorf("missing exported module %s", module)
				}
			}
		})
	}
}

func TestGradlePublicationExportsResolvedRepository(t *testing.T) {
	requireTool(t, "java")
	proj := copyGradleFixture(t, "gradle-library")
	out := filepath.Join(t.TempDir(), "publication")
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{"JAVA_HOME": detectJavaHome(t)}}, "build", "gradle", "export-publications", "--version", "2.1.0", "--output", out, "--central")
	if code != 0 {
		t.Fatalf("Gradle publication export: %d: %s", code, stderr)
	}
	for _, suffix := range []string{".pom", ".jar", "-sources.jar", "-javadoc.jar"} {
		filename := filepath.Join(out, "org", "example", "test", "gradle-library", "2.1.0", "gradle-library-2.1.0"+suffix)
		if !fileExists(filename) {
			t.Errorf("missing resolved publication %s", filename)
		}
	}
	_, stderr, code = run(t, runOpts{dir: proj}, "publish", "maven-central", "validate-publication", "--working-dir", out, "--version", "2.1.0")
	if code != 0 {
		t.Fatalf("publication validation: %d: %s", code, stderr)
	}
}

func TestGradlePublicationSelectsExactProject(t *testing.T) {
	requireTool(t, "java")
	for _, version := range []string{"2.1.0", "2.1.1-SNAPSHOT"} {
		t.Run(version, func(t *testing.T) {
			project := copyGradleFixture(t, "gradle-multi-library")
			if err := os.WriteFile(filepath.Join(project, "gradle.properties"), []byte("version="+version+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// An unselected sibling must neither be version-checked nor exported.
			if err := os.WriteFile(filepath.Join(project, "beta", "build.gradle"), []byte("publishing.publications.library.version = '9.9.9'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "publication")
			args := []string{"build", "gradle", "export-publications", "--project", ":alpha", "--version", version, "--output", out}
			if strings.HasSuffix(version, "-SNAPSHOT") {
				args = append(args, "--snapshot")
			}
			_, stderr, code := run(t, runOpts{dir: project, env: map[string]string{"JAVA_HOME": detectJavaHome(t)}}, args...)
			if code != 0 {
				t.Fatalf("selected project export: %d: %s", code, stderr)
			}
			if !fileExists(filepath.Join(out, "org/example/fixture/alpha", version, "alpha-"+version+".pom")) {
				t.Fatal("selected publication missing")
			}
			entries, err := os.ReadDir(filepath.Join(out, "org/example/fixture"))
			if err != nil || len(entries) != 1 || entries[0].Name() != "alpha" {
				t.Fatalf("unexpected exported projects: %v: %v", entries, err)
			}
		})
	}
}
