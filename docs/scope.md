<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Why the suite exists and what it covers

## Why it exists

The Go unit tests inside `forge-ci/internal/...` cover internal contracts
(parsers, planners, error classifications). They cannot catch:

- Failures that only surface when the real toolchain runs (`syft`,
  `cyclonedx-gomod`, `cyclonedx-gradle-plugin`, `cargo-cyclonedx`, `gpg`,
  `git`).
- Reproducibility: the same input must give byte-identical output across runs.
- Cross-ecosystem consistency: does `--json` emit a deterministic schema for
  both Go and Maven?
- Host isolation: does a developer's `~/.gitconfig` (for example
  `gpg.format=ssh`) change a test's outcome?

This suite drives the binary as a black box and checks the artifacts it
produces: files produced, exit codes, JSON schemas, and signatures verifiable
by `sha256sum --check` or `gpg --verify`.

## Which tier this is

These are black-box CLI tests. The compiled binary runs as a subprocess against
real tools (git, gpg, ssh-keygen, cosign, syft, the language toolchains). Forge
APIs and SSH transport are local fakes, but package tools may download
dependencies, plugins, distributions, or base images on a cold isolated cache.
They receive no real credentials or user settings.

This is the black-box tier, not end-to-end. The end-to-end layer, a real CI
runner talking to a real forge, lives in separate pipelines and in real
releases, not in this repository. Keep the word "e2e" for those.

## Rebuild evidence

Reproducibility is tested where forge-ci owns the input that makes a build
repeatable. `build go run` injects `SOURCE_DATE_EPOCH` into the binary, so the
Go tests build in separate source directories with independent compiler caches
and compare the binaries. `container build --source-date-epoch` clamps image
timestamps, so a scratch image built through forge-ci is exported to fresh OCI
layouts and the manifest digests are compared, after each config and layer blob
is checked against its digest. Both also change the epoch and require a
different result. Whether Maven, Gradle, Cargo or npm repeat their own outputs
is the toolchain's property, not forge-ci's, and is not tested here; `validate
jvm-reproducibility` covers the JVM project settings forge-ci checks. Missing
tools still skip with NOT PROVEN in the optional profile and fail in the strict
profile.

## Deliberate exclusions

- `xcode-ios`: needs a macOS toolchain, so it can't run on the Linux CI this
  suite targets.
- Publishing to real stores and registries (Maven Central, Google Play, App
  Store, npm): no trustworthy sandbox exists. The engine's flag and plan
  validation covers the argv, and real releases cover the rest.
- Forge API behaviour (release upload, package listing): belongs to the
  platform-integration tests that run against a real forge, not to this suite.

## What is tested where

| Concern | Test location |
|---|---|
| Per-ecosystem build + SBOM behaviour against real toolchains | testsuite (this repository) |
| Reproducibility of forge-ci-built Go binaries and container images | testsuite (`build_go_test.go`, `container_build_reproducibility_test.go`) |
| `release sign --method=gpg` round-trip | testsuite (`release_sign_test.go`) |
| `release sign --method=kms` + `validate artifact-signature` round-trip | testsuite (`release_sign_cosign_test.go`) |
| `release sign --method=sigstore` (keyless via OIDC) | **not here**. Needs live Fulcio and Rekor; argv pinning is unit-tested in `forge-ci/internal/adapters/cosign` |
| `container sign`, `container attest` and private base validation with real Cosign signature, CycloneDX and SLSA evidence | testsuite (`container_private_bases_test.go`), authenticated loopback registry, no public Sigstore services; the standalone `validate container-signature` command remains outside this scenario |
| Prepared private parent transfer, cold native build and warm cache reuse without registry access | testsuite (`container_prepared_inputs_test.go`), real OCI bytes and native Buildah; refusal and tamper checks included |
| `forge-ci doctor` setup-check command | testsuite (`doctor_test.go`, recommendations and the calling-workflow check) + parent repository (`forge-ci/cmd/forge-ci/smoke_test.go`) |
| `forge-ci setup status` step list, agreeing with doctor | testsuite (`setup_test.go`) |
| `forge-ci docs` pages built into the binary | testsuite (`docs_test.go`) |
| `plan release` runner-input refusal, the release APK of an Android application in the transfer plan, and `plan release-file-signing` (GPG or Cosign for checksums and SBOMs) | testsuite (`plan_release_test.go`) |
| Exit-code classes, including 78 for a missing tool and 69 only for an unreachable host | testsuite (`cli_exit_codes_test.go`) |
| `container validate artifacts` presence gate (JVM, Go and Cargo container-packaging path) | testsuite (`container_validate_artifacts_test.go`) |
| `container validate image-names` and `container validate rebuilds` advisory warnings, clean cases and zero exit status | testsuite (`container_validate_warnings_test.go`); no image build or pull |
| Android SBOM-layer defaults and refusal of unavailable analyzed-artifact layers | testsuite (`config_android_sboms_test.go`); no Android toolchain |
| Release asset-retention dry run preserves current and legacy proof files and sends no deletion requests | testsuite (`release_asset_retention_test.go`); loopback fake Forgejo API, no live deletion |
| SLSA workflow-hardening validators: `validate isolation` (L3 job isolation), `validate event-context` (trigger allowlist), `validate job-graph` (masked-failure guard), `validate pin-reachability` (orphaned pins) | testsuite (`validate_isolation_test.go`, `validate_event_context_test.go`, `validate_job_graph_test.go`, `validate_pin_reachability_test.go`) |
| `release provenance` SLSA-v1.0 statement generation (shape, subjects, determinism, reserved-key guard) | testsuite (`release_provenance_test.go`). Signing the statement needs OIDC/KMS and is **not here** |
| Build->sign tamper-evidence digests: `artifact digest` (canonical content digest), `release dist-digest` + `release prepare-dist` (hand-off digest, shell-pipeline byte-compat, CI-sink emission) | testsuite (`artifact_digest_test.go`, `release_dist_digest_test.go`) |
| Workflow-input-contract (caller `with:` keys match callee `inputs:`) | parent repository (`forge-ci/internal/workflowguard/workflowcontract_test.go`) |
| YAML schema for `artifacts.yml` (including the `sign:` block) | parent repository (`forge-ci/internal/app/config/schema_test.go`) |
| install-forge-ci.sh cosign-verify behaviour | parent repository (`forge-ci/scripts/bootstrap/install-forge-ci_test.sh`) |
| Release authorization (allowed_signers / allowed_gpg_keys.asc) | testsuite (`validate_signer_allowlist_test.go`) |
| Sigstore-keyless + container signing in CI | exercised by the parent repository's own self-release flow on every tag |
