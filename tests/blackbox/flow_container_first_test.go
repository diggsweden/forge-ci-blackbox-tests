// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box cascade tests for the container-first flow:
//
//   sbom build-layer (lockfile-derived) → container build →
//   extracted binary → analyzed-artifact SBOM → checksums → sign
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
// TestFlow_ContainerFirst_Cargo walks the cascade with a real Buildah build.
// TestFlow_ContainerFirst_BuildSBOMHeldAtTheHandoff covers the hand-off
// directory every forge's container-first release uses for the build SBOM.

package blackbox

import (
	"debug/elf"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	// The builder base is pulled from Docker Hub on a cold store.
	allowEgress(t, dockerHubHosts()...)
	requireWorkingTool(t, "cargo", "--version")
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
		"--file", binaryRelative); code != 0 {
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
	for _, subj := range []string{
		"checksums.sha256",
		binaryRelative,
	} {
		asc := subj + ".asc"
		ascPath := filepath.Join(proj, asc)

		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", asc)

			continue
		}

		verify := toolCommand(t, proj, map[string]string{"GNUPGHOME": key.gnupgHome},
			"gpg", "--verify", ascPath, filepath.Join(proj, subj))

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", asc, err, out)
		}
	}
}

// TestFlow_ContainerFirst_BuildSBOMHeldAtTheHandoff drives the path every
// forge's container-first release takes: `sbom assemble --artifacts-config`
// writes the planned artifact's build SBOM from its lockfile into a hand-off
// directory, leaving the checkout clean, and `release files validate
// --artifacts-config` refuses a hand-off whose SBOM bundle lacks it.
func TestFlow_ContainerFirst_BuildSBOMHeldAtTheHandoff(t *testing.T) {
	t.Parallel()

	requireTool(t, "go")
	requireTool(t, "cyclonedx-gomod")

	const config = ".forge-ci/artifacts.yml"

	for name, sboms := range map[string][]string{"declared": {"--sbom", "dist/sboms/*"}, "undeclared": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			proj := copyTree(t, fixture("go-hello"))
			writeHandoffFile(t, filepath.Join(proj, config),
				"artifacts:\n  - name: go-hello\n    project-type: go\n    config:\n      build-mode: container-first\n")
			writeHandoffFile(t, filepath.Join(proj, "dist", "go-hello-linux-amd64"), "binary\n")

			if _, stderr, code := run(t, runOpts{dir: proj}, "sbom", "assemble", "--artifacts-config", config,
				"--project-type", "go", "--version", "v0.1.0", "--output-dir", "dist/sboms"); code != 0 {
				t.Fatalf("sbom assemble exit %d\nstderr: %s", code, stderr)
			}

			assertValidCycloneDXJSON(t, filepath.Join(proj, "dist", "sboms", "go-hello-0.1.0-build-sbom.cyclonedx.json"))

			if _, err := os.Stat(filepath.Join(proj, ".forge-ci", "go-build-sbom")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("sbom assemble left its working file in the checkout: %v", err)
			}

			declare := append([]string{"release", "files", "declare", "--project-name", "go-hello", "--version", "v0.1.0",
				"--asset", "dist/go-hello-linux-amd64"}, sboms...)
			if _, stderr, code := run(t, runOpts{dir: proj}, declare...); code != 0 {
				t.Fatalf("declare exit %d\nstderr: %s", code, stderr)
			}

			_, stderr, code := run(t, runOpts{dir: proj}, "release", "files", "validate", "--unsigned", "--artifacts-config", config)
			if sboms != nil {
				if code != 0 {
					t.Fatalf("validate refused the declared build SBOM, exit %d\nstderr: %s", code, stderr)
				}

				return
			}

			if code != exitValidation || !strings.Contains(stderr, "no build SBOM of the container-first go-hello") {
				t.Fatalf("validate exit %d, want the missing build SBOM refused\nstderr: %s", code, stderr)
			}
		})
	}
}

// writeHandoffFile writes one file of a test's project, creating its parents.
func writeHandoffFile(t *testing.T, path, body string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
