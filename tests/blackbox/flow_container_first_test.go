// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box cascade tests for the container-first flow:
//
//   sbom build-layer (lockfile-derived) → container build OR direct
//   compile → extracted binary in release-artifacts/ → analyzed-
//   artifact SBOM → checksums → sign
//
// Distinct from artifact-first because:
//
//   1. The build-layer SBOM comes from the lockfile (Cargo.lock /
//      go.sum) via cargo-cyclonedx / cyclonedx-gomod, NOT from
//      build observation.
//   2. The "artifact" is a binary extracted from the container,
//      named with the -<os>-<arch> convention used by `extract.
//      binary` (so multi-arch matrix uploads don't collide).
//   3. There is no `release-build-stage` step for these
//      ecosystems — sbom-cargo.yml / sbom-go.yml run in
//      `release-publish-stage` alongside the container build.
//
// The Cargo variant uses real buildah (skips when buildah is
// missing) to exercise the full path through `publish-container.
// yml`'s reproducibility plumbing. The Go variant uses host
// `go build` directly to keep the test fast —
// TestContainerImage_ReproducibleImageID already covers a real local Buildah
// round-trip, so the cost of running it twice isn't justified.

package blackbox

import (
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func assertNativeLinuxArtifact(t *testing.T, path string) {
	t.Helper()

	binary, err := elf.Open(path)
	if err != nil {
		t.Fatalf("read extracted ELF: %v", err)
	}
	defer func() { _ = binary.Close() }()

	var machine elf.Machine
	switch runtime.GOARCH {
	case "amd64":
		machine = elf.EM_X86_64
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		t.Fatalf("no native ELF expectation for %s", runtime.GOARCH)
	}
	if binary.Class != elf.ELFCLASS64 || binary.Machine != machine {
		t.Fatalf("artifact is %s/%s, want native linux/%s", binary.Class, binary.Machine, runtime.GOARCH)
	}
}

// TestFlow_ContainerFirst_Cargo runs the full container-first
// cascade for Cargo, including a real buildah build with
// --timestamp pinning. Asserts:
//
//   - the lockfile-derived build-layer SBOM (cargo-cyclonedx)
//     promotes correctly into <name>-<version>-build-sbom.cyclonedx.json
//   - buildah's `--target=export-binary --output=type=local,...`
//     produces the binary at the expected name
//   - the syft analyzed-binary SBOM lands next to it
//   - checksums + sign work through the real local CLI and tools
func TestFlow_ContainerFirst_Cargo(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")
	requireTool(t, "buildah")
	requireTool(t, "syft")
	requireTool(t, "gpg")
	requireTool(t, "sha256sum")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("cargo-hello"))
	binaryName := "cargo-hello-linux-" + runtime.GOARCH
	binaryRelative := filepath.Join("dist", binaryName)

	// 1. Build-layer SBOM: cargo-cyclonedx writes bom.json; forge-ci
	//    promotes it. This step normally runs in sbom-cargo.yml in
	//    release-publish-stage (sibling of the container build),
	//    not before/during it — but the cascade order is preserved
	//    in the test for determinism.
	// --format json because forge-ci's build-layer discovery
	// looks for `*/bom.json`. cargo-cyclonedx defaults to XML.
	if _, _, code := runTool(t, proj, "cargo", "cyclonedx", "--format", "json", "--override-filename", "bom"); code != 0 {
		t.Fatalf("step 1 cargo-cyclonedx exit %d", code)
	}

	if _, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "cargo",
		"--layers", "build",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 1 build-sbom promotion exit %d\nstderr: %s", code, stderr)
	}

	buildSBOM := filepath.Join(proj, "cargo-hello-0.3.1-build-sbom.cyclonedx.json")
	assertValidCycloneDXJSON(t, buildSBOM)

	// 2. Container build with --timestamp pinning. Extract the
	//    binary via the export-binary scratch stage. This is the
	//    `extract.binary` path from publish-container.yml.
	//    NB: dest must NOT be ./release-artifacts/ — that's the
	//    default --release-artifacts-dir, and the release-checksums
	//    walk would emit a duplicate basename-only entry that
	//    breaks `sha256sum --check`. Use ./dist/ instead.
	extract := filepath.Join(proj, "dist")
	if err := os.MkdirAll(extract, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, stderr, code := runBuildah(t, proj, "build",
		"--platform", "linux/"+runtime.GOARCH,
		"--timestamp", "1700000000",
		"--target", "export-binary",
		"--output", "type=local,dest="+extract,
		"-f", "Containerfile", "."); code != 0 {
		t.Fatalf("step 2 buildah failed for pinned builder rust:1.94.0-slim-bookworm (exit %d):\n%s", code, stderr)
	}

	// Rename binary to the multi-arch convention extract.binary
	// emits: <name>-linux-<arch>.
	if err := os.Rename(
		filepath.Join(extract, "cargo-hello"),
		filepath.Join(extract, binaryName),
	); err != nil {
		t.Fatalf("step 2 rename: %v", err)
	}
	// Inspect the exported target independently of the controller's libc;
	// the builder image supplies the Linux GNU runtime ABI.
	assertNativeLinuxArtifact(t, filepath.Join(extract, binaryName))

	// 3. Analyzed-artifact SBOM over the extracted binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "cargo",
		"--layers", "analyzed-artifact",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 3 analyzed sbom exit %d", code)
	}

	analyzedSPDX := globOne(t, proj, "*analyzed-binary-sbom.spdx.json")
	assertValidSPDXJSON(t, analyzedSPDX)
	assertValidCycloneDXJSON(t, globOne(t, proj, "*analyzed-binary-sbom.cyclonedx.json"))

	// 4. Checksums covering binary + build-SBOM + analyzed-SBOM.
	//    Use --attach-artifacts so the binary's path stays
	//    verbatim in the manifest — sha256sum --check runs from
	//    cwd and needs that path to resolve.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", binaryRelative,
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 4 checksums exit %d", code)
	}

	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"),
		binaryName, filepath.Base(buildSBOM), filepath.Base(analyzedSPDX))

	// 5. Sign the binary + manifest.
	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	}, "release", "sign",
		"--attach-artifacts", binaryRelative); code != 0 {
		t.Fatalf("step 5 sign exit %d\nstderr: %s", code, stderr)
	}

	// 6. Manifest round-trip + signature verification.
	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 6 sha256sum --check: %v\n%s", err, out)
	}

	// Both signatures, not just the manifest's. The binary is what this flow
	// exists to produce and what consumers verify; step 5 signs it, so leaving
	// its .asc unchecked meant a sign step that mis-targeted or truncated the
	// binary signature passed while the manifest half still looked right.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: binaryName + ".asc", subj: binaryRelative},
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

// TestFlow_ContainerFirst_Go runs the equivalent cascade for Go.
// Uses host `go build` instead of buildah to keep this test fast
// (TestContainerImage_ReproducibleImageID already covers the buildah path
// in this local black-box suite). The cascade contract is identical: lockfile-SBOM
// → extracted binary → analyzed-binary SBOM → checksums → sign.
func TestFlow_ContainerFirst_Go(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")
	requireTool(t, "cyclonedx-gomod")
	requireTool(t, "syft")
	requireTool(t, "gpg")
	requireTool(t, "sha256sum")

	key := bootstrapGPGKey(t)

	proj := copyTree(t, fixture("go-hello"))

	// 1. Build-layer SBOM via forge-ci build go sbom. For Go
	//    artifact-first, this lives in `release-build-stage`. For
	//    Go container-first it would run in `sbom-go.yml` during
	//    publish stage. Either way, the binary it produces is the
	//    `*/bom.json` forge-ci promotes.
	if _, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "build", "--project-type", "go", "--name", "go-hello"); code != 0 {
		t.Fatalf("step 1 build go sbom exit %d\nstderr: %s", code, stderr)
	}

	// 2. Promote into the canonical build-layer name.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "go",
		"--layers", "build",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 2 build-sbom promotion exit %d", code)
	}

	buildSBOM := filepath.Join(proj, "go-hello-0.1.0-build-sbom.cyclonedx.json")
	assertValidCycloneDXJSON(t, buildSBOM)

	// 3. Compile the binary (simulating what extract.binary would
	//    produce out of the container's export-binary stage).
	//    NB: using `./dist/` (not `./release-artifacts/`) because
	//    release checksums walks --release-artifacts-dir (default
	//    `./release-artifacts/`) and would emit a duplicate entry
	//    with basename-only label, breaking sha256sum --check.
	extract := filepath.Join(proj, "dist")
	if err := os.MkdirAll(extract, 0o755); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(extract, "go-hello-linux-amd64")
	if _, _, code := runToolEnv(t, proj, map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
		"go", "build", "-trimpath", "-buildvcs=false", "-o", bin, "./"); code != 0 {
		t.Fatalf("step 3 go build exit %d", code)
	}

	// 4. Analyzed-artifact SBOM over the extracted binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "assemble",
		"--project-type", "go",
		"--layers", "analyzed-artifact",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 4 analyzed sbom exit %d", code)
	}

	// Validate the SPDX header on the analyzed-binary SBOM.
	assertValidSPDXJSON(t, filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.spdx.json"))

	// 5. Checksums + 6. Sign + 7. Verify. --attach-artifacts keeps
	//    the binary's path verbatim so sha256sum --check from cwd
	//    resolves it (dist/go-hello-linux-amd64).
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/go-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 5 checksums exit %d", code)
	}

	assertChecksumManifestLists(t, filepath.Join(proj, "checksums.sha256"),
		"go-hello-linux-amd64", filepath.Base(buildSBOM), "go-hello-linux-amd64-analyzed-binary-sbom.spdx.json")

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: key.signingEnv(t),
	}, "release", "sign",
		"--attach-artifacts", "dist/go-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 6 sign exit %d\nstderr: %s", code, stderr)
	}

	cmd := toolCommand(t, proj, nil, "sha256sum", "--check", "checksums.sha256")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 7 sha256sum --check: %v\n%s", err, out)
	}

	// Step 6 asserted only that `release sign` exited 0 — no signature was ever
	// looked at, so a sign step that wrote nothing passed this cascade. Verify
	// both signatures with real gpg, as every artifact-first cascade does.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "go-hello-linux-amd64.asc", subj: "dist/go-hello-linux-amd64"},
	} {
		ascPath := filepath.Join(proj, pair.asc)

		if !fileExists(ascPath) {
			t.Errorf("step 7 missing signature %s", pair.asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 7 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}
