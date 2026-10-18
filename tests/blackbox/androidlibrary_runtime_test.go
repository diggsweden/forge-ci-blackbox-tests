// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

// The SDK is an immutable container input. This test installs no host SDK and
// uses the suite's existing isolated Buildah store, not the developer's store.
func TestAndroidLibraryBuildAndExportInPinnedRuntime(t *testing.T) {
	requireTool(t, "buildah")
	project := copyGradleFixture(t, "android-library")
	if err := copyFile(binPath, filepath.Join(project, "forge-ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	_, stderr, code := runBuildah(t, project, "bud", "--isolation", "chroot", "--network", "host", "--layers", "--force-rm", "--build-arg", "JVM_PROXY_OPTS="+egressJVMProxyOpts(), "--output", "type=local,dest="+output, "--file", "Containerfile", ".")
	if code != 0 {
		t.Fatalf("Android runtime build: %d: %s", code, stderr)
	}
	assertValidCycloneDXJSON(t, filepath.Join(output, "bom.json"))
	publication := filepath.Join(output, "publication")
	_, stderr, code = run(t, runOpts{dir: project}, "publish", "maven-central", "validate-publication", "--working-dir", publication, "--version", "1.2.3")
	if code != 0 {
		t.Fatalf("Android publication validation: %d: %s", code, stderr)
	}
	_, stderr, code = run(t, runOpts{dir: project}, "publish", "maven-central", "snapshot", "--working-dir", filepath.Join(output, "snapshot-publication"), "--validate-only")
	if code != 0 {
		t.Fatalf("Android snapshot validation: %d: %s", code, stderr)
	}
	aar := filepath.Join(publication, "org/example/fixture/android-library-fixture/1.2.3/android-library-fixture-1.2.3.aar")
	archive, err := zip.OpenReader(aar)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = archive.Close() }()
	classes, err := archive.Open("classes.jar")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = classes.Close() }()
	body, err := io.ReadAll(classes)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	class, err := jar.Open("demo/Library.class")
	if err != nil {
		t.Fatal("AAR does not contain the compiled Android SDK consumer: " + err.Error())
	}
	_ = class.Close()
}
