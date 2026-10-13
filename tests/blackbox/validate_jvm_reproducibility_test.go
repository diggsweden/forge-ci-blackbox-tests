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

// TestValidateJVMReproducibility_MavenPasses runs the new validator
// against the maven-hello fixture (which sets
// <project.build.outputTimestamp> in its POM) and asserts the
// validator reports it as configured. Counterpart to the on-disk
// reproducibility test in reproducibility_test.go — this one tests
// the policy-check surface that the release-prerequisites stage runs.
func TestValidateJVMReproducibility_MavenPasses(t *testing.T) {
	t.Parallel()

	proj := copyTree(t, fixture("maven-hello"))

	plan := producedConfigPlan(t, proj, "maven-hello", "maven")

	// The validator writes diagnostic output to stderr (the "w"
	// parameter the CLI binds to os.Stderr — same pattern as
	// `validate cargo`). stdout is reserved for structured output.
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "validate", "jvm-reproducibility")
	if code != 0 {
		t.Fatalf("validate exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "pass marker", stderr, "outputTimestamp=")

	if strings.Contains(stderr, "::warning") {
		t.Errorf("unexpected ::warning for properly-configured fixture, got:\n%s", stderr)
	}
}

// TestValidateJVMReproducibility_GradlePasses runs the validator
// against the gradle-hello fixture (which sets
// preserveFileTimestamps=false + reproducibleFileOrder=true).
func TestValidateJVMReproducibility_GradlePasses(t *testing.T) {
	t.Parallel()

	proj := copyTree(t, fixture("gradle-hello"))

	plan := producedConfigPlan(t, proj, "gradle-hello", "gradle")

	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "validate", "jvm-reproducibility")
	if code != 0 {
		t.Fatalf("validate exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "pass marker", stderr, "preserveFileTimestamps=false")

	if strings.Contains(stderr, "::warning") {
		t.Errorf("unexpected ::warning for properly-configured fixture, got:\n%s", stderr)
	}
}

// TestValidateJVMReproducibility_MissingTimestampFails verifies the
// negative path on a stripped-down POM (no outputTimestamp). The
// reproducibility setting is a hard gate — the deployable-pipeline
// contract treats determinism as foundational, so a non-reproducible
// JVM artifact cannot pass `validate prerequisites`.
func TestValidateJVMReproducibility_MissingTimestampFails(t *testing.T) {
	t.Parallel()

	proj := t.TempDir()

	pom := []byte(`<?xml version="1.0"?>
<project><modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version>
</project>`)
	if err := os.WriteFile(filepath.Join(proj, "pom.xml"), pom, 0o600); err != nil {
		t.Fatal(err)
	}

	plan := producedConfigPlan(t, proj, "a", "maven")

	// --format github forces the annotator into ::error:: prefix
	// regardless of the surrounding env (the run helper unsets
	// GITHUB_ACTIONS by default to keep tests host-independent).
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "--format", "github", "validate", "jvm-reproducibility")
	if code != exitValidation {
		t.Errorf("missing outputTimestamp: exit %d, want 1 (EX_VALIDATION) — the pipeline gates on this code, "+
			"and a bare non-zero check would also accept a usage error or a crash\nstderr: %s", code, stderr)
	}

	assertContains(t, "error annotation", stderr, "::error")

	assertContains(t, "fix snippet", stderr, "<project.build.outputTimestamp>")
}

// TestValidateJVMReproducibility_GradleMissingSettingsFails is the Gradle
// counterpart of the Maven negative above, which nothing covered.
//
// The two ecosystems are checked by separate rules — Maven reads
// <project.build.outputTimestamp> from the POM, Gradle looks for
// preserveFileTimestamps=false / reproducibleFileOrder=true in the build
// script — so the Maven negative says nothing about Gradle. A regression that
// stopped checking Gradle altogether would leave BOTH Gradle tests green:
// _GradlePasses passes on a correctly-configured fixture whether or not the
// rule runs, and the Maven negative is a different rule.
func TestValidateJVMReproducibility_GradleMissingSettingsFails(t *testing.T) {
	t.Parallel()

	proj := t.TempDir()

	if err := os.WriteFile(filepath.Join(proj, "build.gradle"), []byte("plugins { id \"java\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	plan := producedConfigPlan(t, proj, "g", "gradle")

	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "--format", "github", "validate", "jvm-reproducibility")

	if code != exitValidation {
		t.Errorf("missing Gradle reproducibility settings: exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
	}

	assertContains(t, "error annotation", stderr, "::error")

	// Both settings must be named: an operator told only one of them fixes
	// half the problem and gets a second failure on the next run.
	for _, want := range []string{"preserveFileTimestamps=false", "reproducibleFileOrder=true"} {
		assertContains(t, "fix guidance", stderr, want)
	}
}

// producedConfigPlan writes a one-artifact .forge-ci/artifacts.yml into
// dir and returns the config plan `config parse-artifacts` produces for it.
//
// The plan used to be assembled by hand. The engine validates a plan against
// what its producer would have computed (every artifact's sboms, its build
// artifact name, the pipeline union), so a hand-built envelope is refused
// before the validator under test runs, and it drifts every time the plan
// gains a field. Asking the producer is what the workflows do.
func producedConfigPlan(t *testing.T, dir, name, projectType string) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(dir, ".forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	body := "artifacts:\n  - name: " + name + "\n    project-type: " + projectType + "\n    working-directory: .\n"
	if err := os.WriteFile(filepath.Join(dir, ".forge-ci", "artifacts.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return configPlanJSON(t, dir)
}
