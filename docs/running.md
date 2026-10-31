<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Running the suite

## The engine under test

This suite is the independent companion for the Forge CI 0.90.0 baseline. The
default engine is the sibling `../forge-ci` checkout, which the suite builds
itself. `FORGE_CI_TEST_BINARY` selects an explicit binary instead.

Custom launchers must use `FORGE_CI_TEST_BINARY` instead of the former
`FORGE_CI` override, and update their immutable companion pin together with the
caller. The suite checks the binary's public name before treating it as Forge
CI evidence.

## Requirements

- Go 1.27.2 or newer, to run `go test`.
- A checkout of the chosen Forge CI engine as the sibling `forge-ci` directory,
  or `FORGE_CI_TEST_BINARY` pointing at a pre-built binary.
- Optional for the default developer profile: `mvn`, `npm`, `cargo`,
  `buildah`, `gpg`/`gpgconf`, `syft`, `cyclonedx-gomod`, `cargo-cyclonedx`, and
  the JDK (`java` and `javac`), Git, Cosign, Bash, `sha256sum`, `ssh-keygen`
  and the fixture Gradle wrapper.
  Anything missing makes only the dependent tests
  skip.
- Linux for the strict profile. Its Buildah, `/proc`, and strict compatibility
  contracts are not a portable macOS or Windows gate, so its preflight refuses
  other hosts before building forge-ci.

For strict runs, install every tool above, including Node for npm, the Rust
compiler for Cargo, and the OCI runtime/rootless prerequisites below. A local
pass with missing tools is diagnostic evidence only, not the strict gate.

Run `just install-dev-tools` and use `mise exec -- just ...` when mise is not
activated. The declared JDK is needed by both Maven and Gradle. macOS's
`/usr/bin/java` is a system launcher, not proof that a JDK is installed; the
Gradle fixture queries `java.home` with a bounded runtime probe and checks for
both `java` and `javac`. It never derives `JAVA_HOME` from a launcher path.
The default Go build also needs the pinned cyclonedx-gomod SBOM generator.
Setup also supplies the CI-pinned Rust compiler, cargo-cyclonedx, Syft and
Cosign. It activates the compiler for Cargo-tool installation without relying
on a pre-existing rustup default. On macOS, install GnuPG separately with
`sudo port install gnupg2`; run Buildah scenarios on a matching-architecture
Linux host. Missing-tool evidence remains visible under the optional profile.

Buildah needs a working OCI runtime such as `crun` or `runc`, and the host's
normal rootless-user namespace configuration. An absent Buildah skips the
container scenarios in the developer profile, but a present Buildah that fails
a build is broken evidence, not missing evidence: the container-first flow
fails in every profile. The container jobs select
the native CPU architecture explicitly: AMD64 runs on AMD64 hosts, ARM64 on
ARM64 hosts. Do not enable cross-architecture emulation to satisfy this lane.

## Forks and fixture identities

The suite's repository name and the engine's repository name are independent.
For the compatibility workflow, set `FORGE_CI_REPOSITORY` to your engine's
`owner/repository` and `FORGE_CI_REF` to its default branch or desired revision.
Manual workflow inputs override those defaults. Keep the parent engine
workflow's companion commit pin explicit; a moving drift target and an
immutable release-gate pin serve different purposes.

The workflow records a full resolved SHA-1 or SHA-256 commit ID. A hosting
migration must establish the destination object format and commit IDs;
shortening a SHA-256 ID or assuming push converts history is not a substitute.
Port the provider-specific checkout/runner configuration when moving the
workflow between GitHub and Forgejo; changing the repository variable alone
does not change the forge hosting the workflow.

The strict-profile contract check reads `.forgejo/workflows/integration.yml`
when the Forgejo workflow directory exists, otherwise the GitHub file. It
checks the repository/ref override contract without requiring the original
organization's fallback values. A missing active workflow is an error, even
if an inactive GitHub copy remains.

Locally, clone the chosen engine into the sibling directory named `forge-ci`,
regardless of its remote repository name, or build that checkout yourself and
set `FORGE_CI_TEST_BINARY` to the resulting executable. This avoids adding
another source-selection mechanism beside the existing binary override.

Synthetic fixture coordinates use `fixture/integration`, `@fixture/npm-app`,
`@fixture/npm-lib`, and the JVM groups `org.example.test` or
`org.example.fixture`. They are test identities, not real publication accounts.
Use reserved example domains for new inert URLs and loopback test servers for
actual registry/API calls. Keep manifests, lockfiles, expected archive names,
SBOM paths and simulated API paths consistent when changing a fixture identity.
Preserve upstream provenance identifiers and source/license attribution where
they identify the real project rather than synthetic test data.

## Commands

```bash
# Run the whole suite. In the default profile, toolchain-dependent tests skip
# when their tools are unavailable. -v shows PASS/SKIP/FAIL lines as they happen.
go test -tags=blackbox -count=1 -v ./tests/blackbox/...

# Strict compatibility evidence: no partial runs or Buildah fallback.
FORGE_CI_BLACKBOX_PROFILE=strict \
  go test -tags=blackbox -count=1 -timeout 35m ./tests/blackbox/...

# Run one test (or one pattern):
go test -tags=blackbox -count=1 -run TestFlow_ContainerFirst_Go -v ./tests/blackbox/
```

The `//go:build blackbox` tag is the opt-in switch. Without `-tags=blackbox`,
`go test ./...` ignores this package, so it won't run by accident while you
test forge-ci itself.

## Profiles

The empty/default profile keeps optional skips for developer diagnostics and
reports them once at the end as NOT PROVEN.

The named `strict` profile turns skips into failures: a row that would skip for
a missing tool or missing evidence (Gradle wrapper, Java path, Git SHA-256
support) fails instead. `TestMain`:

- refuses a profile value other than empty or `strict`;
- refuses test-selection flags, so a filtered run cannot pass as the gate;
- requires the local recording egress proxy to start.
  `BLACKBOX_EGRESS_PROXY=off` is permitted only for optional local
  diagnostics;
- refuses a non-Linux host, after the checks above.

Explicit Linux exclusions remain exclusions; strict mode does not turn them
into claimed coverage.

Engine and tool scenario subprocesses have a 10-minute context deadline;
version probes and the suite binary build have tighter limits.

## Strict-profile contract check

`bash scripts/validate-strict-profile-contract.sh` is the fast contract check,
run by the compatibility workflow before the suite. It compiles the package
test binary but does not build forge-ci or run the suite. It:

- checks active-workflow selection and the workflow's drift-target overrides;
- proves with negative probes against the compiled `TestMain` that
  `-test.run` and disabled strict egress auditing are rejected;
- exercises bounded stream draining, per-file and aggregate evidence
  truncation, sealing reserve, and the post-seal upload limit.

It needs no providers, network access, containers, or large permanent
fixtures.
Its negative probes use a private temporary root, so they can run while a
developer suite holds its own cache lock. The evidence scripts exercise GNU
coreutils and findutils semantics. On macOS use MacPorts Bash and those utilities:

```bash
sudo port install bash coreutils findutils
PATH="/opt/local/libexec/gnubin:/opt/local/bin:$PATH" \
  mise exec -- bash scripts/validate-strict-profile-contract.sh
```

## just recipes

The `justfile` wraps the same commands, in the shape the forge-ci repository
uses. `just` on its own lists everything.

```bash
just install-dev-tools                   # install the pinned tools (mise install)
just verify-fix                          # apply safe fixes, then lint and test
just verify                              # lint + local suite, with skips shown
just test                                # local suite; containers/downloads possible
just test-strict                         # strict CI compatibility profile
just test-run TestFlow_ContainerFirst_Go # tests matching a name filter
just test-binary /path/to/forge-ci       # test a pre-built binary (sets FORGE_CI_TEST_BINARY)
just lint                                # justfile + gofmt checks, go vet, golangci-lint
just lint-fix                            # format justfile/Go, apply golangci fixes
just clean                               # drop cached toolchain/buildah state
```

`verify` and `test` default to the permissive local profile; the CI
compatibility gate uses `strict`. Available tools can run containers and fetch
dependencies, plugins or images even in the local profile. All test recipes
default to verbose output so passing packages retain SKIP and NOT PROVEN
evidence; they still run every selected test. Builds and tools write caches.

`test-binary` accepts a literal executable-file path, including spaces.
Relative paths are resolved from the recipe working directory (normally this
checkout) before Go or engine subprocesses change directories. Invalid paths
fail before Go starts. It preserves an inherited `FORGE_CI_BLACKBOX_PROFILE`,
including strict's refusal of test-selection flags. Direct
`FORGE_CI_TEST_BINARY` overrides passed to `go test` should use an absolute
path.

`bash scripts/test-justfile.sh` checks prebuilt-path handling, argument
forwarding, profile preservation and failure propagation using an inert Go
stand-in, without building or running the engine.

## Common gotchas

For a focused retry, use `just test-run TestName` in the local profile; strict
mode intentionally refuses filters. After Ctrl-C or a killed run, confirm no
suite is using the caches, follow the printed lock-removal command, then run
`just clean`. See [Stopping a run](isolation.md#stopping-a-run) for details.

- **"package diggsweden/forge-ci/cmd/forge-ci not found"**: the sibling
  `forge-ci/` directory is missing. Clone it next to this repository, or set
  `FORGE_CI_TEST_BINARY=/path/to/forge-ci-binary` to point at a pre-built
  binary.
- **Lots of `--- SKIP` in the default developer profile**: expected unless you
  have the full toolchain installed. Each test names the missing tool or
  evidence. Strict mode fails rather than skipping any of these paths.
- **"buildah build failed"** in the cargo container-first test: inspect the
  emitted Buildah stderr. The compatibility fixture selects the versioned
  `docker.io/library/rust:1.94.0-slim-bookworm` tag; a cold cache may need to
  resolve and fetch its current image.

What a run does to your machine, and how to stop one, is in
[Host isolation and footprint](isolation.md). The CI run is in [CI](ci.md).
