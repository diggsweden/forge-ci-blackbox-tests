// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Reproducible-build coverage matrix.
//
// These tests compare SHA-256 hashes from two consecutive local builds of the
// same fixture with the same declared inputs and available toolchain. They
// exercise project and toolchain prerequisites for repeatability; they do not
// establish reproducibility across machines or environments.
//
// Per-ecosystem and per-artifact fixture coverage follows. The listed knobs are
// the inputs these fixtures rely on, not a guarantee for other projects.
//
//   ┌──────────┬──────────────────┬─────────────────────────────────────────────────┐
//   │ ECOSYS   │ ARTEFACT         │ KNOB / SOURCE                                    │
//   ├──────────┼──────────────────┼─────────────────────────────────────────────────┤
//   │ Go       │ binary (x-arch)  │ -trimpath -buildvcs=false + SOURCE_DATE_EPOCH    │
//   │          │                  │ ldflag (forge-ci injects this for us).        │
//   │ Maven    │ main jar         │ <project.build.outputTimestamp> in POM. Maven    │
//   │          │ sources jar      │  3.6+; sources jar inherits the same property.   │
//   │ Gradle   │ jar / war        │ preserveFileTimestamps=false,                    │
//   │          │ distZip / distTar│  reproducibleFileOrder=true on AbstractArchive-  │
//   │          │                  │  Task (build.gradle).                            │
//   │ NPM      │ .tgz (npm pack)  │ npm ≥ 10 (npm/cli#3536 fix). No project knob —   │
//   │          │                  │  bug fix in the packer itself.                   │
//   │ Cargo    │ release binary   │ Stock cargo + fixed toolchain. Cargo doesn't     │
//   │          │ .crate package   │  embed the wall clock; lockfile is the input.    │
//   │ Container│ OCI image config │ buildah --timestamp <epoch> (or                  │
//   │          │ + layer blobs    │  docker/build-push-action SOURCE_DATE_EPOCH).    │
//   │          │                  │  Image-config digest + layer diff_id are stable. │
//   └──────────┴──────────────────┴─────────────────────────────────────────────────┘
//
// References:
//   - reproducible-builds.org/docs/source-date-epoch
//   - maven.apache.org/guides/mini/guide-reproducible-builds.html
//   - docs.gradle.org/current/userguide/working_with_files.html#sec:reproducible_archives
//   - github.com/npm/cli/pull/3536 (npm-side fix)
//   - docs.podman.io/en/latest/markdown/buildah-build.1.html (--timestamp)

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMavenBuild_Reproducible verifies that two `mvn package` runs of the
// maven-lib fixture produce byte-identical artifacts for BOTH the main JAR and
// the sources JAR attached by the project-owned plugin. The fixture POM sets
// <project.build.outputTimestamp>; without that property this test
// would fail (jar manifests carry wall-clock mtimes).
func TestMavenBuild_Reproducible(t *testing.T) {
	requireTool(t, "mvn")

	proj := copyTree(t, fixture("maven-lib"))

	build := func() map[string]string {
		_, _, code := runTool(t, proj, "mvn", "-B", "-ntp", "package", "-DskipTests")
		if code != 0 {
			t.Fatalf("mvn package exit %d", code)
		}

		hashes := map[string]string{}

		main := globMust(filepath.Join(proj, "target"), "maven-lib-1.0.0.jar")
		if len(main) != 1 {
			t.Fatalf("expected exactly 1 main jar; got %v", main)
		}

		hashes["main.jar"] = sha256File(t, main[0])

		sources := globMust(filepath.Join(proj, "target"), "maven-lib-1.0.0-sources.jar")
		if len(sources) != 1 {
			t.Fatalf("expected exactly 1 sources jar; got %v", sources)
		}

		hashes["sources.jar"] = sha256File(t, sources[0])

		return hashes
	}

	first := build()

	if err := os.RemoveAll(filepath.Join(proj, "target")); err != nil {
		t.Fatal(err)
	}

	second := build()

	for k := range first {
		if first[k] != second[k] {
			t.Errorf("Maven %s not reproducible:\n  first:  %s\n  second: %s\n"+
				"Check that <project.build.outputTimestamp> is set in the POM.",
				k, first[k], second[k])
		}
	}
}

// TestGradleArchives_Reproducible verifies the same property for
// gradle-hello across the full set of archive artifacts: the
// library JAR plus the distZip and distTar produced by the
// application plugin. They all flow through AbstractArchiveTask so
// one configuration block covers them all.
func TestGradleArchives_Reproducible(t *testing.T) {
	requireTool(t, "java")

	proj := copyTree(t, fixture("gradle-hello"))

	if !fileExists(filepath.Join(proj, "gradlew")) {
		skipInOptionalProfilef(t, "gradlew not present in fixture (need a JDK + network to bootstrap)")
	}

	build := func() map[string]string {
		_, _, code := runTool(t, proj, "./gradlew", "--no-daemon", "--quiet",
			"jar", "distZip", "distTar")
		if code != 0 {
			t.Fatalf("gradlew exit %d", code)
		}

		hashes := map[string]string{}

		jars := globMust(filepath.Join(proj, "build", "libs"), "*.jar")
		if len(jars) != 1 {
			t.Fatalf("expected exactly 1 jar; got %v", jars)
		}

		hashes["jar"] = sha256File(t, jars[0])

		for _, ext := range []string{"zip", "tar"} {
			matches := globMust(filepath.Join(proj, "build", "distributions"), "*."+ext)
			if len(matches) != 1 {
				t.Fatalf("expected exactly 1 dist.%s; got %v", ext, matches)
			}

			hashes["dist."+ext] = sha256File(t, matches[0])
		}

		return hashes
	}

	first := build()

	if err := os.RemoveAll(filepath.Join(proj, "build")); err != nil {
		t.Fatal(err)
	}

	second := build()

	for k := range first {
		if first[k] != second[k] {
			t.Errorf("Gradle %s not reproducible:\n  first:  %s\n  second: %s\n"+
				"Check preserveFileTimestamps/reproducibleFileOrder on AbstractArchiveTask.",
				k, first[k], second[k])
		}
	}
}

// TestCargoBinary_Reproducible verifies cargo's release-profile binaries
// are byte-identical across runs when SOURCE_DATE_EPOCH is fixed.
// Cargo doesn't directly read SOURCE_DATE_EPOCH for the binary, but
// for a fixed toolchain + lockfile the output is deterministic.
func TestCargoBinary_Reproducible(t *testing.T) {
	requireTool(t, "cargo")

	proj := copyTree(t, fixture("cargo-hello"))

	env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}

	build := func() string {
		_, _, code := runToolEnv(t, proj, env, "cargo", "build", "--release")
		if code != 0 {
			t.Fatalf("cargo build exit %d", code)
		}

		bin := filepath.Join(proj, "target", "release", "cargo-hello")
		if !fileExists(bin) {
			t.Fatalf("expected binary at %s", bin)
		}

		return sha256File(t, bin)
	}

	first := build()

	if err := os.RemoveAll(filepath.Join(proj, "target")); err != nil {
		t.Fatal(err)
	}

	second := build()

	if first != second {
		t.Errorf("Cargo binary not reproducible:\n  first:  %s\n  second: %s",
			first, second)
	}
}

// TestCargoCrate_Reproducible verifies the published crate package
// (`cargo package`) is byte-identical across runs. Distinct from
// the binary test above: `.crate` files are the source-archive
// units Cargo uploads to crates.io. Reproducibility here matters
// for registry-integrity validators that re-package a tag and
// compare hashes.
func TestCargoCrate_Reproducible(t *testing.T) {
	requireTool(t, "cargo")

	proj := copyTree(t, fixture("cargo-hello"))

	pack := func() string {
		_, _, code := runTool(t, proj, "cargo", "package", "--allow-dirty")
		if code != 0 {
			t.Fatalf("cargo package exit %d", code)
		}

		matches := globMust(filepath.Join(proj, "target", "package"), "*.crate")
		if len(matches) != 1 {
			t.Fatalf("expected exactly 1 .crate; got %v", matches)
		}

		return sha256File(t, matches[0])
	}

	first := pack()

	if err := os.RemoveAll(filepath.Join(proj, "target", "package")); err != nil {
		t.Fatal(err)
	}

	second := pack()

	if first != second {
		t.Errorf("Cargo .crate not reproducible:\n  first:  %s\n  second: %s",
			first, second)
	}
}

// TestContainerImage_ReproducibleImageID verifies the OCI image config
// digest (= the canonical "image ID" registries report) is stable
// across two buildah runs of the same Containerfile with the same
// `--timestamp <epoch>`. Note that the OCI archive *file* SHA will
// differ between runs because the archive tar embeds filesystem
// metadata around the layer blobs — what matters is the image
// content (config + layer blob digests), which IS reproducible.
//
// Skips when buildah is missing. Buildah is used in preference to
// `docker buildx` because it doesn't require a running daemon.
func TestContainerImage_ReproducibleImageID(t *testing.T) {
	requireTool(t, "buildah")

	proj := t.TempDir()

	if err := os.WriteFile(filepath.Join(proj, "Containerfile"),
		[]byte("FROM scratch\nCOPY payload /payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(proj, "payload"),
		[]byte("reproducible-payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	build := func(tag string) string {
		_, _, code := runBuildah(t, proj, "build",
			"--timestamp", "1700000000",
			"-t", tag,
			"-f", "Containerfile", ".")
		if code != 0 {
			t.Fatalf("buildah build exit %d", code)
		}

		stdout, _, code := runBuildah(t, proj, "inspect",
			"--type", "image",
			"--format", "{{.FromImageID}}",
			tag)
		if code != 0 {
			t.Fatalf("buildah inspect exit %d", code)
		}

		id := strings.TrimSpace(stdout)
		if id == "" {
			t.Fatalf("empty image ID")
		}

		return id
	}

	first := build("repro-test-a:1")
	defer func() { _, _, _ = runBuildah(t, proj, "rmi", "repro-test-a:1") }()

	second := build("repro-test-b:1")
	defer func() { _, _, _ = runBuildah(t, proj, "rmi", "repro-test-b:1") }()

	if first != second {
		t.Errorf("OCI image config digest not reproducible:\n  first:  %s\n  second: %s\n"+
			"Check that buildah --timestamp <epoch> is honoured by the local buildah build.",
			first, second)
	}

	// The control, in the direction this test cannot otherwise prove. Two equal
	// image IDs are consistent with reproducibility AND with the second build
	// never happening — a cache hit handing back the first image, or a
	// --timestamp buildah quietly ignored, would both produce this pass.
	//
	// A third build differing only in --timestamp must therefore differ: that
	// shows the ID responds to the input the other two hold fixed, so their
	// agreement is a result rather than an artefact. It is the same reasoning
	// as TestSourceDateEpoch_ChangesGoBinaryHash, applied to the one other
	// toolchain where forge-ci pins the date itself.
	third := build("repro-test-c:1")
	defer func() { _, _, _ = runBuildah(t, proj, "rmi", "repro-test-c:1") }()

	if third != first {
		t.Fatalf("control build with the same inputs disagreed: %s vs %s", third, first)
	}

	shifted := func() string {
		_, _, code := runBuildah(t, proj, "build",
			"--timestamp", "1800000000",
			"-t", "repro-test-shifted:1",
			"-f", "Containerfile", ".")
		if code != 0 {
			t.Fatalf("buildah build (shifted timestamp) exit %d", code)
		}

		stdout, _, code := runBuildah(t, proj, "inspect",
			"--type", "image", "--format", "{{.FromImageID}}", "repro-test-shifted:1")
		if code != 0 {
			t.Fatalf("buildah inspect (shifted timestamp) exit %d", code)
		}

		return strings.TrimSpace(stdout)
	}()

	defer func() { _, _, _ = runBuildah(t, proj, "rmi", "repro-test-shifted:1") }()

	if shifted == first {
		t.Errorf("a different --timestamp produced the same image ID (%s) — the timestamp is not "+
			"reaching the image config, so the equality above is not evidence of reproducibility", first)
	}
}

// TestNPMPack_Reproducible verifies that two `npm pack` runs produce
// byte-identical tarballs. Historically this was NOT the case — npm
// recorded each file's on-disk mtime without honouring
// SOURCE_DATE_EPOCH (tracked at npm/cli#3536). Modern npm (≥10) has
// fixed it; this test pins that behaviour so a regression in the
// upstream packer becomes visible immediately.
func TestNPMPack_Reproducible(t *testing.T) {
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-lib"))

	env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}

	pack := func() string {
		_, _, code := runToolEnv(t, proj, env, "npm", "pack")
		if code != 0 {
			t.Fatalf("npm pack exit %d", code)
		}

		matches := globMust(proj, "*.tgz")
		if len(matches) != 1 {
			t.Fatalf("expected exactly 1 tarball; got %v", matches)
		}

		return sha256File(t, matches[0])
	}

	first := pack()

	for _, m := range globMust(proj, "*.tgz") {
		if err := os.Remove(m); err != nil {
			t.Fatal(err)
		}
	}

	second := pack()

	if first != second {
		t.Errorf("npm pack not reproducible:\n  first:  %s\n  second: %s\n"+
			"If the host npm is older than v10, that may be the cause "+
			"(npm/cli#3536). For modern npm, this is a regression worth filing upstream.",
			first, second)
	}
}

// TestSourceDateEpoch_ChangesGoBinaryHash verifies the
// "negative" direction of reproducibility: a different
// SOURCE_DATE_EPOCH must change the artifact hash. Without this
// guard, a build could be "accidentally reproducible" simply
// because the date wasn't being baked in at all.
//
// Covered for the toolchains where forge-ci itself injects the
// date (Go is the only one — Maven/Gradle/Cargo read
// SOURCE_DATE_EPOCH directly from their own infrastructure).
func TestSourceDateEpoch_ChangesGoBinaryHash(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")

	proj := copyTree(t, fixture("go-hello"))

	compile := func(epoch string) string {
		_, _, code := run(t, runOpts{dir: proj, env: map[string]string{"SOURCE_DATE_EPOCH": epoch, "GITHUB_SHA": "abc1234"}},
			"build", "go", "run", "--version", "v0.1.0", "--platforms", "linux/amd64")
		if code != 0 {
			t.Fatalf("compile exit %d", code)
		}

		return sha256File(t, filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64"))
	}

	a := compile("1700000000")

	if err := os.RemoveAll(filepath.Join(proj, "dist")); err != nil {
		t.Fatal(err)
	}

	b := compile("1800000000")

	if a == b {
		t.Errorf("changing SOURCE_DATE_EPOCH did not change Go binary SHA — the date is not being baked in")
	}
}
