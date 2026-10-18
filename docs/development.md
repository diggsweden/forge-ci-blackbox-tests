<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Development

## Adding a new test

1. Add a `Test*` function to the matching file, or create a new
   `<command-group>_<feature>_test.go` with the `//go:build blackbox` tag (see
   [Where a test goes](layout.md#where-a-test-goes)).
2. Use `run()` for the binary call, `copyTree(t, fixture("…"))` for per-test
   fixture isolation, and `requireTool(t, "name")` to skip when an optional
   toolchain is absent.
3. Open the doc comment with the flow you cover, the inputs you build, and
   what you assert. That header is the coverage doc; there is no separate
   table to keep in sync.
4. Route engine calls through `run()`, which gives them the isolated
   environment and the subprocess deadline.
5. Call `t.Parallel()` first when the test needs nothing beyond Go, git, gpg,
   ssh-keygen, syft and coreutils. A test that runs Maven, Gradle, npm, cargo,
   Buildah or cosign, directly or through the engine, stays serial: those
   tools share the isolated home's Maven repository, package caches, Buildah
   store and Sigstore state. A test that calls `t.Setenv` stays serial by rule.
6. If the CLI adds a top-level command group, add an explicit covered or
   excluded disposition and reason in `commandGroupCoverage()`.
7. Run `bash scripts/validate-strict-profile-contract.sh` before proposing a
   parent pin. A focused `-run` result is developer diagnostics, never strict
   gate evidence.

## Helpers

All in `helpers_test.go` and `keys_test.go`:

- `run(t, runOpts{dir, env}, args...)` runs the binary in an isolated
  environment.
- `fixture("go-hello")` resolves a path under the testsuite root.
- `copyTree(t, src)` clones a fixture into `t.TempDir()`, preserving exec
  bits.
- `bootstrapGPGKey(t)` and `bootstrapSSHKey(t)` create throwaway signing keys.
- `initGitRepo(t, env, configure)` makes a fresh repository with
  host-isolated git config.
- `requireTool(t, "syft")` skips when the tool is unavailable.

What the isolated environment does is in
[Host isolation and footprint](isolation.md).

## Lint

`just lint` runs `just --fmt --check`, gofmt, `go vet`, and golangci-lint. The
linter set in `.golangci.yml` is the forge-ci engine's, so the suite is held to
the same bar as the code it tests.

The config sets the `blackbox` build tag itself, so golangci-lint sees the same
code the tests do. It also excludes the findings that are inherent to a
black-box suite rather than working around them in the tests: launching
subprocesses (`G204`), fixture paths built from `t.TempDir()` (`G304`,
`G703`), walking fixture trees (`G122`), fixture file permissions (`G301`,
`G302`, `G306`), and the helper-layer idioms (`nonamedreturns`, `unparam`,
table-driver complexity). Each exclusion carries its reason in the config.

`.mise.toml` is the authority for runtime, lint, signing and SBOM-tool versions.
Java, Rust, Syft, Cosign and the SBOM generators use the compatibility workflow's
pins. Run `just install-dev-tools`, then `mise exec -- just lint` (or activate
mise in the shell).

Setup first installs Go, Java and Rust, then activates those pinned runtimes
with `mise exec --no-deps` while installing the remaining tools. Cargo tools
therefore build without requiring a global rustup default. Cargo-cyclonedx
retains its locked dependency build, as in CI. GnuPG is a host-package
prerequisite; Buildah belongs to the native Linux lane.
