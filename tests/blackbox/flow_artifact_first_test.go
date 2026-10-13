// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box cascade tests for the artifact-first flow:
//
//   build metadata → build artifact → SBOM (build + analyzed-artifact)
//   → checksums → sign → verify
//
// Each step's output feeds the next. The value of these tests over
// the per-step slice tests is catching contract drift between
// adjacent steps — e.g. the SBOM filename convention must match
// what `release checksums --sbom-dir` discovers, the artifact dir
// must align with what `release sign --release-artifacts-dir`
// expects, and the GPG key plumbing must thread through both.

package blackbox

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestFlow_ArtifactFirst_MavenApp runs the canonical cascade for a
// Maven application project. Asserts every output that the next step
// consumes is present and well-formed.
func TestFlow_ArtifactFirst_MavenApp(t *testing.T) {
	requireTool(t, "mvn")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("maven-hello"))

	// 1. build maven application → target/<name>-<version>.jar
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "run", "--build-type", "app", "--cli-opts", "-B -ntp", "--skip-tests", "--build-sbom=false"); code != 0 {
		t.Fatalf("step 1 build exit %d\nstderr: %s", code, stderr)
	}

	mainJar := filepath.Join(proj, "target", "maven-hello-1.0.0.jar")
	if !fileExists(mainJar) {
		t.Fatalf("step 1 missing main jar at %s", mainJar)
	}

	// 2. sbom generate all --layers=analyzed-artifact
	//    (build-layer stubbing isn't part of this cascade — caller
	//    runs cyclonedx-maven-plugin during the build, which this
	//    fixture doesn't to keep the test under 30s; analyzed-
	//    artifact is the layer this cascade exercises.)
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "maven",
		"--layers", "analyzed-artifact",
		"--name", "maven-hello", "--version", "1.0.0"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	spdx := filepath.Join(proj, "maven-hello-1.0.0-analyzed-jar-sbom.spdx.json")
	cdx := filepath.Join(proj, "maven-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json")

	assertValidSPDXJSON(t, spdx)
	assertValidCycloneDXJSON(t, cdx)

	// 3. release checksums via --attach-artifacts (the real
	//    workflow's mode: ATTACH_ARTIFACTS env, paths kept verbatim).
	//    --release-artifacts-dir would strip the target/ prefix and
	//    break sha256sum --check, which runs relative to cwd.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "target/maven-hello-1.0.0.jar",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	manifest := filepath.Join(proj, "checksums.sha256")
	if !fileExists(manifest) {
		t.Fatalf("step 3 missing %s", manifest)
	}

	assertChecksumManifestLists(t, manifest, "maven-hello-1.0.0.jar",
		"maven-hello-1.0.0-analyzed-jar-sbom.spdx.json", "maven-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json")

	// 4. release sign — same --attach-artifacts shape. .asc files
	//    land in cwd per the sign subcommand's contract.
	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	},
		"release", "sign",
		"--attach-artifacts", "target/maven-hello-1.0.0.jar"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. verify the manifest round-trips through sha256sum --check.
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. verify GPG detached signatures on the jar AND the manifest.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "maven-hello-1.0.0.jar.asc", subj: "target/maven-hello-1.0.0.jar"},
	} {
		ascPath := filepath.Join(proj, pair.asc)

		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtifactFirst_MavenLib mirrors the app cascade but uses
// the library shape. The extra contract here: the sources and javadoc
// jars must be built, checksummed, and each get a detached signature,
// not just the main jar. (An earlier version of this comment promised a
// "sources SBOM pair" — the engine has no such concept; sbom assemble
// analyzes the main artifact only, and its pair is asserted below.)
func TestFlow_ArtifactFirst_MavenLib(t *testing.T) {
	requireTool(t, "mvn")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("maven-lib"))

	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "run", "--build-type", "lib", "--cli-opts", "-B -ntp", "--skip-tests", "--build-sbom=false"); code != 0 {
		t.Fatalf("library build exit %d\nstderr: %s", code, stderr)
	}

	for _, suffix := range []string{".jar", "-sources.jar", "-javadoc.jar"} {
		if !fileExists(filepath.Join(proj, "target", "maven-lib-1.0.0"+suffix)) {
			t.Fatalf("missing maven-lib-1.0.0%s", suffix)
		}
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "maven",
		"--layers", "analyzed-artifact",
		"--name", "maven-lib", "--version", "1.0.0"); code != 0 {
		t.Fatalf("sbom exit %d", code)
	}

	// Match the production workflow pattern (ATTACH_ARTIFACTS) so
	// paths in the manifest stay relative to cwd and round-trip
	// through sha256sum --check.
	attach := "target/maven-lib-1.0.0.jar,target/maven-lib-1.0.0-sources.jar,target/maven-lib-1.0.0-javadoc.jar"
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", attach,
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	// The SBOM-to-checksums filename contract is the drift this cascade
	// exists to catch; the app cascade asserts it and the lib one must too.
	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"),
		"maven-lib-1.0.0.jar", "maven-lib-1.0.0-sources.jar", "maven-lib-1.0.0-javadoc.jar",
		"maven-lib-1.0.0-analyzed-jar-sbom.spdx.json", "maven-lib-1.0.0-analyzed-jar-sbom.cyclonedx.json")

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	},
		"release", "sign",
		"--attach-artifacts", attach); code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	// .asc files land in cwd (the sign subcommand's contract). Each one is
	// verified with gpg, as the other cascades do: a sidecar that exists but
	// does not verify is exactly what a mis-targeted sign step leaves behind.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "maven-lib-1.0.0.jar.asc", subj: "target/maven-lib-1.0.0.jar"},
		{asc: "maven-lib-1.0.0-sources.jar.asc", subj: "target/maven-lib-1.0.0-sources.jar"},
		{asc: "maven-lib-1.0.0-javadoc.jar.asc", subj: "target/maven-lib-1.0.0-javadoc.jar"},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtifactFirst_Gradle runs the canonical cascade for a
// Gradle JVM project: build → SBOM → checksums → sign → verify.
// Same contract as the Maven cascade; the value here is catching
// drift in the gradle-specific outputs (build/libs/ vs Maven's
// target/) and confirming the jar lands where downstream steps
// expect it.
func TestFlow_ArtifactFirst_Gradle(t *testing.T) {
	requireTool(t, "java")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("gradle-hello"))

	if !fileExists(filepath.Join(proj, "gradlew")) {
		skipInOptionalProfilef(t, "gradlew not present in fixture (gradle wrapper bootstrap needs JDK + network)")
	}

	// 1. build gradle application → build/libs/<name>-<version>.jar
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "gradle", "run",
		"--tasks", "build", "--skip-tests", "--build-sbom=false"); code != 0 {
		t.Fatalf("step 1 gradle build exit %d\nstderr: %s", code, stderr)
	}

	// gradle-hello pins its version in gradle.properties; the SBOM
	// step extracts the version from the jar filename, so the asserted
	// SBOM names below must match that — not the --version flag.
	mainJar := globOne(t, filepath.Join(proj, "build", "libs"), "gradle-hello-*.jar")
	jarVersion := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(mainJar), "gradle-hello-"), ".jar")

	// 2. analyzed-artifact SBOM via syft on the produced jar.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "gradle",
		"--layers", "analyzed-artifact",
		"--name", "gradle-hello", "--version", jarVersion); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	for _, suffix := range []string{".spdx.json", ".cyclonedx.json"} {
		path := filepath.Join(proj, "gradle-hello-"+jarVersion+"-analyzed-jar-sbom"+suffix)
		if !fileExists(path) {
			t.Fatalf("step 2 missing SBOM at %s", path)
		}
	}

	// 3. checksums + 4. sign. Use the jar's actual relative path so
	// sha256sum --check round-trips.
	relJar, err := filepath.Rel(proj, mainJar)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", relJar,
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"), filepath.Base(mainJar))

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	},
		"release", "sign",
		"--attach-artifacts", relJar); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the jar + manifest signatures.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: filepath.Base(mainJar) + ".asc", subj: relJar},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtifactFirst_GoBinary runs the artifact-first Go cascade:
// cross-compile platform-specific binaries, SBOM each one, checksum,
// sign, verify. This is the path used by Go CLI releases where the
// binary is the deliverable (not wrapped in a container).
//
// Distinct from container-first Go (covered by TestFlow_ContainerFirst_Go)
// which compiles inside the Containerfile.
func TestFlow_ArtifactFirst_GoBinary(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("go-hello"))

	// 1. build go compile → dist/<goos>-<goarch>/<binary>-<goos>-<goarch>
	//    Single-platform to keep the test fast; the multi-platform
	//    matrix is exercised by build_go_test.go's reproducibility cascade.
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "go", "run",
		"--version", "v0.1.0",
		"--platforms", "linux/amd64"); code != 0 {
		t.Fatalf("step 1 go compile exit %d\nstderr: %s", code, stderr)
	}

	binary := filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64")
	if !fileExists(binary) {
		t.Fatalf("step 1 missing compiled binary at %s", binary)
	}

	// 2. analyzed-artifact SBOM via syft on the binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "go",
		"--layers", "analyzed-artifact",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	// 3. checksums covering the binary + 4. sign.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/linux-amd64/go-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	// The SBOM pair as well as the binary: an empty --sbom-dir is a no-op for
	// checksums, so without these two rows a silently SBOM-less step 2 would
	// pass the whole cascade.
	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"), "go-hello-linux-amd64",
		"go-hello-linux-amd64-analyzed-binary-sbom.spdx.json", "go-hello-linux-amd64-analyzed-binary-sbom.cyclonedx.json")

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	},
		"release", "sign",
		"--attach-artifacts", "dist/linux-amd64/go-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the binary's signature + the manifest signature.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "go-hello-linux-amd64.asc", subj: "dist/linux-amd64/go-hello-linux-amd64"},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtifactFirst_CargoBinary mirrors the Go-binary cascade for
// Cargo: cross-compile, SBOM, checksum, sign, verify. The dist/ layout
// matches Go intentionally so downstream packaging works uniformly.
//
// Linux/amd64 only — multi-platform cross-compile needs `rustup target
// add` and a matching cross-linker baked into the runtime image, which
// is exercised in CI not in the local testsuite.
func TestFlow_ArtifactFirst_CargoBinary(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("cargo-hello"))

	// 1. build cargo compile → dist/<goos>-<goarch>/<binary>-<goos>-<goarch>
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "cargo", "run",
		"--version", "v0.3.1",
		"--platforms", "linux/amd64"); code != 0 {
		t.Fatalf("step 1 cargo compile exit %d\nstderr: %s", code, stderr)
	}

	binary := filepath.Join(proj, "dist", "linux-amd64", "cargo-hello-linux-amd64")
	if !fileExists(binary) {
		t.Fatalf("step 1 missing compiled binary at %s", binary)
	}

	// 2. analyzed-artifact SBOM via syft on the binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "cargo",
		"--layers", "analyzed-artifact",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	// 3. checksums covering the binary + 4. sign.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/linux-amd64/cargo-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	// Same rationale as the Go cascade: pin the SBOM pair, not just the binary.
	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"), "cargo-hello-linux-amd64",
		"cargo-hello-linux-amd64-analyzed-binary-sbom.spdx.json", "cargo-hello-linux-amd64-analyzed-binary-sbom.cyclonedx.json")

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	},
		"release", "sign",
		"--attach-artifacts", "dist/linux-amd64/cargo-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the binary's signature + the manifest signature.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "cargo-hello-linux-amd64.asc", subj: "dist/linux-amd64/cargo-hello-linux-amd64"},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtifactFirst_NPM runs the NPM publish-shape cascade:
// pack the package into a tarball, generate the analyzed-artifact
// SBOM over it, checksum, sign, verify.
//
// There is deliberately no "app" vs "lib" variant here: unlike Maven,
// the engine models no build-type for NPM (NPMConfig carries no such
// field), so every NPM project releases the same way — `npm pack`
// tarball → forge-packages, optionally COPY'd into a container. An
// NPM "application" differs only in that its package.json build script
// runs before the pack, which is covered by build_type_test.go, not by
// a second release cascade that would be byte-for-byte this one.
func TestFlow_ArtifactFirst_NPM(t *testing.T) {
	requireTool(t, "npm")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("npm-lib"))

	if _, _, code := run(t, runOpts{dir: proj}, "build", "npm", "pack"); code != 0 {
		t.Fatalf("npm pack exit %d", code)
	}

	tgz := globMust(proj, "*.tgz")
	if len(tgz) != 1 {
		t.Fatalf("expected one tarball, got %v", tgz)
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "npm",
		"--layers", "analyzed-artifact",
		"--name", "npm-lib", "--version", "0.1.0"); code != 0 {
		t.Fatalf("sbom exit %d", code)
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "*.tgz",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	// The tarball and its SBOM pair (probed naming: npm pack prefixes the
	// scope, and the analyzed layer over a tarball is "tararchive"). An empty
	// --sbom-dir is a no-op for checksums, so without the SBOM rows a silently
	// SBOM-less assemble step would pass the cascade.
	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"), filepath.Base(tgz[0]),
		"diggsweden-npm-lib-0.1.0-analyzed-tararchive-sbom.spdx.json",
		"diggsweden-npm-lib-0.1.0-analyzed-tararchive-sbom.cyclonedx.json")

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	}, "release", "sign", "--attach-artifacts", "*.tgz"); code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	// Round-trip the manifest through sha256sum and verify each signature with
	// gpg so file presence alone cannot satisfy the cascade.
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("sha256sum --check: %v\n%s", err, out)
	}

	tarball := filepath.Base(tgz[0])

	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: tarball + ".asc", subj: tarball},
	} {
		ascPath := filepath.Join(proj, pair.asc)

		if !fileExists(ascPath) {
			t.Errorf("missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}
