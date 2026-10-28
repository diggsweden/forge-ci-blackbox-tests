<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# CI

This suite runs as the local black-box tier above `forge-ci`'s own
`go test ./...`. It catches regressions that only surface against real
toolchains (`syft`, `cyclonedx-gomod`, `cargo-cyclonedx`, `gpg`,
`gradle/java`, `mvn`, `cargo`), which unit tests can't reach.

## The compatibility workflow

The pipeline in `.github/workflows/integration.yml` is strict compatibility
evidence for the selected Forge CI source contract. Its default parent ref
is mutable on purpose so drift is found quickly; every run records the
exact commit it resolved. It is not the immutable release gate.

| Trigger | forge-ci ref tested | Purpose |
|---|---|---|
| `workflow_dispatch` (manual) | `forge-ci-repository` plus `forge-ci-ref`; empty values fall back to the defaults below | Ad-hoc validation, including coordinated repository forks |
| `push` to any branch | the default target | Catch testsuite-side regressions |
| `pull_request` into any branch | the default target | Pre-merge gate for testsuite changes |
| `schedule` (04:00 UTC daily) | the default target | Catch regressions in forge-ci itself that landed since the last push |

The default target is the `FORGE_CI_REPOSITORY` and `FORGE_CI_REF` repository
variables, falling back to `diggsweden/forge-ci` at the mutable `main` branch.
Nothing depends on either repository's default branch, so a fork can point its
suite at any repository and branch by setting the two variables. After
`v0.90.0` ships, move floating compatibility to released tags; immutable
promotion remains an explicit commit-SHA operation.

Review the engine and companion revisions together when a command contract
changes. The current suite uses `--release-policy` and exercises in-process SSH
host-key inspection. To test a PR candidate explicitly, build that exact checkout
and set `FORGE_CI_TEST_BINARY` to the absolute path of the resulting executable.
That override takes precedence over building the suite's sibling checkout; it
must identify the candidate under review, not an older release binary.

The repository override is one `owner/name` boundary with canonical default
`diggsweden/forge-ci`; the workflow does not expose independently composable
host or owner fragments. Fork tests should override repository and ref
together.

The workflow runs the strict profile described in
[Running the suite](running.md#profiles), installs the required pinned
toolchain, and uploads the bounded evidence bundle below. It pins the tools it
installs. Its cache is deliberately limited to public Go and Cargo
dependency/build data; it never caches Maven/Gradle/npm homes, Buildah storage,
registry credentials, GPG keyrings, Sigstore roots, or generated signing
material. The workflow source is the authority for step order and timeout
budgets; duplicating that inventory or a completed checklist here would drift.

## Evidence bundle

The workflow records both the requested forge-ci ref and the resolved checkout
commit. It retains, as a uniquely named GitHub Actions artifact:

- sanitized structured `go test -json` events;
- runner identity;
- resolved Buildah image data when available;
- per-file SHA-256 manifests for both checkouts;
- `SHA256SUMS`.

Limits and sealing:

- Test events are bounded to 10 MiB while the complete stream is drained; if
  necessary, the retained JSONL ends with an explicit truncation event.
- Each source manifest is limited to 2 MiB, and retention is 30 days. The
  upload service's artifact SHA-256 is written to the job summary.
- Evidence is written eagerly and the artifact records whether each output is
  present or absent, so a timeout retains real partial evidence instead of
  manufacturing empty image records.
- An oversized auxiliary file is omitted with its original size and limit
  recorded in `evidence-truncations.txt`, so the remaining bounded bundle can
  still be sealed and uploaded instead of losing all evidence.
- Aggregate bounding leaves 128 KiB for status and checksum sealing before
  enforcing the final upload limit.

## Floating inputs

The Gradle distribution and fixture `FROM` references are compatibility
inputs, not immutable release inputs: their upstream checksums/digests are not
stored in this repository and are not guessed. The workflow records Buildah's
resolved image data for each run. These floating inputs are deliberately
excluded from immutable release claims until independently verified pins are
available.

## Reproducing CI locally

Install the required tools first. The explicit swap fixture is preserved.
From this checkout:

```bash
FORGE_CI_BLACKBOX_PROFILE=strict \
FORGE_CI_PROC_SWAPS=/dev/null \
go test -tags=blackbox -count=1 -timeout 35m ./tests/blackbox/...
```

Keep the `forge-ci` checkout as a sibling directory, or set
`FORGE_CI_TEST_BINARY` to an explicit binary. For an intentionally partial
developer diagnostic, omit the strict profile; that result is useful locally
but is not equivalent to strict compatibility evidence or the parent's
immutable release gate.
