// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the new canonical config location and the
// auto-derive fallback. Drives `forge-ci config parse-artifacts`
// against three layouts:
//
//   1. .forge-ci/artifacts.yml present → parsed normally.
//   2. No artifacts.yml, single root manifest → auto-derived plan.
//   3. No artifacts.yml, multiple root manifests → actionable error.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfig_ParsesFromCanonicalLocation verifies the new
// .forge-ci/artifacts.yml path is read by `config parse-artifacts`
// when supplied via $ARTIFACTS_CONFIG.
//
// Exit 0 is not evidence of that on its own: measured, a repository with a
// completely different artifacts.yml also exits 0, and so does one with no
// config at all when auto-derive can synthesise a plan. So the assertion is
// the plan's contents -- which only this file could have produced -- and the
// absence of the auto-derive annotation, which is the one signal separating
// "read the file" from "made a plan up".
func TestConfig_ParsesFromCanonicalLocation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, ".forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A shape auto-derive cannot invent: there is no manifest in this
	// directory for it to read, and the working-directory is explicit.
	body := `artifacts:
  - name: canonical-only
    project-type: maven
    working-directory: .
`
	if err := os.WriteFile(filepath.Join(dir, ".forge-ci", "artifacts.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "--json", "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("config parse-artifacts exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	if strings.Contains(stderr, "auto-derived") {
		t.Errorf("the plan was auto-derived, so the canonical file was not the source:\n%s", stderr)
	}

	artifacts := planArtifacts(t, stdout)
	if len(artifacts) != 1 {
		t.Fatalf("plan has %d artifacts, want the one the file declares", len(artifacts))
	}

	if got := artifacts[0]; got.Name != "canonical-only" || got.ProjectType != "maven" {
		t.Errorf("plan artifact = %+v, want the name and project-type from .forge-ci/artifacts.yml", got)
	}
}

// planArtifact is the identity of one artifact in a config plan.
type planArtifact struct {
	Name        string `json:"name"`
	ProjectType string `json:"project_type"`
}

// planArtifacts decodes the artifacts of the config plan `--json config
// parse-artifacts` printed: the envelope carries the plan as an escaped JSON
// string, so it unwraps twice.
func planArtifacts(t *testing.T, stdout string) []planArtifact {
	t.Helper()

	var plan struct {
		Artifacts struct {
			All []planArtifact `json:"all"`
		} `json:"artifacts"`
	}
	decodeJSON(t, "config plan", unwrapConfigPlan(t, stdout), &plan)

	return plan.Artifacts.All
}

// TestConfig_AutoDerivesFromSingleMavenManifest verifies the
// no-config-file happy path: a repo with just a pom.xml at root
// gets an in-memory Config synthesised. The CLI emits an annotation
// noting that auto-derive ran, so operators can see what happened.
func TestConfig_AutoDerivesFromSingleMavenManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	pom := []byte(`<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>se.digg.test</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
</project>`)
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), pom, 0o600); err != nil {
		t.Fatal(err)
	}

	// No .forge-ci/artifacts.yml — auto-derive must kick in.
	stdout, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "--json", "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("auto-derive should succeed for single root manifest; got exit %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "auto-derived") {
		t.Errorf("expected annotation announcing auto-derive; got:\n%s", stderr)
	}

	// What was derived, not only that something was: the artifact takes the
	// manifest's artifactId and the manifest's ecosystem. An auto-derive that
	// announced itself and produced an empty or generic plan would otherwise
	// pass here.
	artifacts := planArtifacts(t, stdout)
	if len(artifacts) != 1 || artifacts[0].Name != "my-app" || artifacts[0].ProjectType != "maven" {
		t.Errorf("derived artifacts = %+v, want one maven artifact named my-app from the pom", artifacts)
	}
}

// TestConfig_AutoDeriveFailsActionablyOnMultipleManifests verifies
// the polyglot-repo case: zero artifacts.yml + two root manifests →
// explicit error naming both manifests, not a silent "first wins"
// pick.
func TestConfig_AutoDeriveFailsActionablyOnMultipleManifests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "pom.xml"),
		[]byte(`<project><groupId>x</groupId><artifactId>x</artifactId><version>1</version></project>`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "config", "parse-artifacts")
	if code != exitConfig {
		t.Fatalf("multi-manifest auto-derive exit = %d, want %d (EX_CONFIG)\nstderr: %s", code, exitConfig, stderr)
	}

	for _, want := range []string{"multiple manifests", "pom.xml", "package.json"} {
		assertContains(t, "multi-manifest refusal", stderr, want)
	}
}
