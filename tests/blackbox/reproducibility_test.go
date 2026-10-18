// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Reproducible-build coverage matrix.
//
// These tests compare SHA-256 hashes from separate copies of the same fixture
// with the same declared inputs and available toolchain. Build outputs are
// independent; dependency/tool downloads can use the suite's shared caches. They
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
//   │ Container│ OCI config +     │ buildah --timestamp <epoch>, no layer cache;     │
//   │          │ exported manifest│  compare export manifest and verify its blobs.  │
//   │          │ + layer blobs    │  Archive wrapper bytes are outside this check.  │
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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

	build := func() map[string]string {
		proj := copyTree(t, fixture("maven-lib"))
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

	if !fileExists(filepath.Join(fixture("gradle-hello"), "gradlew")) {
		skipInOptionalProfilef(t, "gradlew not present in fixture (need a JDK + network to bootstrap)")
	}

	build := func() map[string]string {
		proj := copyTree(t, fixture("gradle-hello"))
		_, _, code := runTool(t, proj, "./gradlew", "--no-daemon", "--quiet",
			"--no-build-cache", "--no-configuration-cache", "--rerun-tasks", "jar", "distZip", "distTar")
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

	build := func() string {
		proj := copyTree(t, fixture("cargo-hello"))
		env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000", "CARGO_TARGET_DIR": filepath.Join(proj, "target")}
		_, _, code := runToolEnv(t, proj, env, "cargo", "build", "--release", "--locked")
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

	pack := func() string {
		proj := copyTree(t, fixture("cargo-hello"))
		_, _, code := runToolEnv(t, proj, map[string]string{"CARGO_TARGET_DIR": filepath.Join(proj, "target")}, "cargo", "package", "--allow-dirty", "--locked")
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

	second := pack()

	if first != second {
		t.Errorf("Cargo .crate not reproducible:\n  first:  %s\n  second: %s",
			first, second)
	}
}

// TestContainerImage_ReproducibleImageID verifies the OCI image config
// digest (image ID, not the registry manifest digest) is stable
// across two buildah runs of the same Containerfile with the same
// `--timestamp <epoch>`. Note that the OCI archive *file* SHA will
// differ between runs because the archive tar embeds filesystem
// metadata around the layer blobs — what matters is the image
// content is checked separately through an OCI export below.
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
		contextDir := copyTree(t, proj)
		_, _, code := runBuildah(t, contextDir, "build", "--no-cache",
			"--platform", "linux/"+runtime.GOARCH,
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

	export := func(tag string) string {
		layout := filepath.Join(t.TempDir(), "image")
		_, _, code := runBuildah(t, proj, "push", tag, "oci:"+layout+":repro")
		if code != 0 {
			t.Fatalf("buildah OCI export exit %d", code)
		}
		return reproducibleOCIManifest(t, layout)
	}
	if firstManifest, secondManifest := export("repro-test-a:1"), export("repro-test-b:1"); firstManifest != secondManifest {
		t.Errorf("OCI export manifest differs: %s vs %s", firstManifest, secondManifest)
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
		_, _, code := runBuildah(t, proj, "build", "--no-cache",
			"--platform", "linux/"+runtime.GOARCH,
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

// Verify the exported manifest, config and compressed layer blobs, rather than
// treating image-ID equality as proof of the exported OCI artifact's equality.
func reproducibleOCIManifest(t *testing.T, layout string) string {
	t.Helper()
	type descriptor struct {
		Digest string `json:"digest"`
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	body, err := os.ReadFile(filepath.Join(layout, "index.json"))
	if err != nil || json.Unmarshal(body, &index) != nil || len(index.Manifests) != 1 {
		t.Fatalf("expected one OCI manifest: %v\n%s", err, body)
	}
	readBlob := func(d descriptor) []byte {
		digest, ok := strings.CutPrefix(d.Digest, "sha256:")
		if !ok || len(digest) != 64 {
			t.Fatalf("unexpected OCI digest %q", d.Digest)
		}
		path := filepath.Join(layout, "blobs", "sha256", digest)
		if actual := sha256File(t, path); actual != digest {
			t.Fatalf("OCI blob digest mismatch: %s vs %s", actual, digest)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return data
	}
	var manifest struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}
	if err := json.Unmarshal(readBlob(index.Manifests[0]), &manifest); err != nil {
		t.Fatal(err)
	}
	readBlob(manifest.Config)
	if len(manifest.Layers) == 0 {
		t.Fatal("expected a COPY payload layer")
	}
	for _, layer := range manifest.Layers {
		readBlob(layer)
	}
	return index.Manifests[0].Digest
}

// TestNPMPack_Reproducible verifies that two `npm pack` runs produce
// byte-identical tarballs. Historically this was NOT the case — npm
// recorded each file's on-disk mtime without honouring
// SOURCE_DATE_EPOCH (tracked at npm/cli#3536). Modern npm (≥10) has
// fixed it; this test pins that behaviour so a regression in the
// upstream packer becomes visible immediately.
func TestNPMPack_Reproducible(t *testing.T) {
	requireTool(t, "npm")

	env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}

	pack := func() string {
		proj := copyTree(t, fixture("npm-lib"))
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
// This controls the date forge-ci injects into Go ldflags. Other ecosystems
// have their own timestamp mechanisms; setting the environment alone is not proof.
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
