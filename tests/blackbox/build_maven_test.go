// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
)

// TestMavenMetadata_SingleModule verifies the metadata path for a
// single-module Maven project. forge-ci reads pom.xml directly
// (no mvn subprocess) and emits typed JSON outputs.
func TestMavenMetadata_SingleModule(t *testing.T) {
	proj := copyTree(t, fixture("maven-hello"))

	stdout, _, code := run(t, runOpts{dir: proj}, "--json", "build", "maven", "metadata")
	if code != 0 {
		t.Fatalf("metadata exit %d", code)
	}

	var got struct {
		Version    string `json:"version"`
		GroupID    string `json:"group-id"`
		ArtifactID string `json:"artifact-id"`
		IsSnapshot bool   `json:"is-snapshot"`
	}
	decodeJSON(t, "maven metadata", stdout, &got)

	if got.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", got.Version)
	}

	if got.GroupID != "se.digg.test" {
		t.Errorf("group-id = %q", got.GroupID)
	}

	if got.ArtifactID != "maven-hello" {
		t.Errorf("artifact-id = %q", got.ArtifactID)
	}

	if got.IsSnapshot {
		t.Errorf("is-snapshot should be false (typed bool)")
	}
}

// TestMavenMetadata_MultiModuleInheritsParentVersion covers parent-pom + child-module
// inheritance:
//   - reading from the root pom returns the parent artifactId
//   - reading from a submodule returns the submodule's artifactId
//     but inherits <version> from <parent>
func TestMavenMetadata_MultiModuleInheritsParentVersion(t *testing.T) {
	proj := copyTree(t, fixture("maven-multi"))

	stdoutRoot, _, codeRoot := run(t, runOpts{dir: proj},
		"--json", "build", "maven", "metadata")
	if codeRoot != 0 {
		t.Fatalf("root metadata exit %d", codeRoot)
	}

	var root struct {
		Version    string `json:"version"`
		ArtifactID string `json:"artifact-id"`
	}
	decodeJSON(t, "root metadata", stdoutRoot, &root)

	if root.Version != "2.0.0" {
		t.Errorf("root version = %q, want 2.0.0", root.Version)
	}

	if root.ArtifactID != "maven-multi-parent" {
		t.Errorf("root artifact-id = %q", root.ArtifactID)
	}

	stdoutCore, _, codeCore := run(t, runOpts{dir: filepath.Join(proj, "core")},
		"--json", "build", "maven", "metadata")
	if codeCore != 0 {
		t.Fatalf("submodule metadata exit %d", codeCore)
	}

	var core struct {
		Version    string `json:"version"`
		ArtifactID string `json:"artifact-id"`
	}
	decodeJSON(t, "submodule metadata", stdoutCore, &core)

	if core.Version != "2.0.0" {
		t.Errorf("submodule should inherit version 2.0.0, got %q", core.Version)
	}

	if core.ArtifactID != "core" {
		t.Errorf("submodule artifact-id = %q, want core", core.ArtifactID)
	}
}
