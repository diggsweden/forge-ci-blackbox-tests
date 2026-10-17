# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: CC0-1.0

# Dev-loop automation for the forge-ci black-box testsuite.
#
# This repo is one build-tagged (`blackbox`) Go test package that drives
# the compiled forge-ci binary as a black box. There is nothing to build
# here — the suite builds the binary itself, from the sibling ../forge-ci
# checkout (override with FORGE_CI_TEST_BINARY=/path/to/binary).
#
# Lint is golangci-lint against .golangci.yml, which carries the engine
# repo's linter set plus the exclusions that a subprocess-driving test
# package needs. The `blackbox` build tag is set in that config, so the
# linter sees the same code the tests do.
#
# Quick start:
#   mise trust               # allow this checkout's pinned toolchain
#   just install-dev-tools   # pinned tools
#   just verify-fix          # apply safe fixes, then lint and test
#   just verify              # lint + permissive local suite (CI uses strict)
#   just test-run FILTER
# Builds/tests write caches, may download dependencies and images, and can run
# containers. Local optional evidence may skip; -v keeps the shortfall visible.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# Color codes used by default and _require-tool.
CYAN_BOLD := "\\033[1;36m"
GREEN := "\\033[1;32m"
BLUE := "\\033[1;34m"
MAGENTA := "\\033[1;35m"
RED := "\\033[1;31m"
NC := "\\033[0m"
pkg := "./tests/blackbox/"

# ==================================================================================== #
# DEFAULT - Show available recipes
# ==================================================================================== #

[private]
default:
    @printf '{{ CYAN_BOLD }} Forge CI black-box testsuite recipes{{ NC }}\n\n Quick start: {{ BLUE }}mise trust{{ NC }} · {{ MAGENTA }}just install-dev-tools{{ NC }} · {{ GREEN }}just verify-fix{{ NC }}\n ▪ main job of its group\n\n'
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --list --unsorted --list-heading ''

# ==================================================================================== #
# SETUP
# ==================================================================================== #

# ▪ Install the pinned development tools; network
[group('setup')]
install-dev-tools:
    @mise install go java rust
    @mise exec --no-deps go java rust -- mise install

# ==================================================================================== #
# DEVELOPMENT - Composite gates
# ==================================================================================== #

# Every lint plus the permissive local suite; CI uses the strict profile.
[doc('▪ Local gate; container, network; may skip')]
[group('development')]
verify: lint test

# Fix files, then run local checks; container, network
[doc('Fix, then verify; container, network')]
[group('development')]
verify-fix: lint-fix verify

# ==================================================================================== #
# TEST - the suite
# ==================================================================================== #
#
# There is one tier here, not several. Every recipe below runs the same
# build-tagged package, ./tests/blackbox; they differ in the profile, in the
# binary under test and in the filter, never in what they cover. Nothing here
# is disjoint from anything else, and `test` is not the union of the others --
# it is the whole suite, and each of the others is that suite under one
# condition.
#
#   test         the local profile: a toolchain-dependent row SKIPS when its
#                tool (mvn, npm, cargo, buildah, gpg, syft, …) is missing, so
#                a bare machine still runs the rest
#   test-strict  the same rows under FORGE_CI_BLACKBOX_PROFILE=strict:
#                a skip for a missing tool or fixture fails instead, the
#                egress audit must run, and test selection is refused
#   test-binary  the same rows against a binary someone else built, rather
#                than the one the suite builds from ../forge-ci
#   test-run     one row, or a family of them, by name
#
# No workflow calls just: this repo's compatibility job runs `go test -json`
# itself so it can redact and bound the stream, and the engine repo's release
# gate sets the strict profile the same way. These recipes are the local
# entry points; verify defaults to the permissive local profile, not CI's strict
# evidence gate. FORGE_CI_BLACKBOX_PROFILE=strict selects strict semantics.
#
# Every recipe forwards its arguments to `go test`, so -v, -count and -timeout
# are arguments rather than recipes of their own. They come after the fixed
# flags, so a caller's -timeout wins over the recipe's. Verbose output defaults
# on for every test recipe so passing packages still show skipped evidence:
#
#   just test -v -timeout 45m
#   just test-binary /tmp/forge-ci -failfast

# The everyday run, and what `verify` gates on: the whole package in the
# local profile.
# ▪ Run the local suite; optional skips, container, network
[doc('▪ Test; container, network; may skip')]
[group('test')]
test *args:
    @go test -tags=blackbox -count=1 -timeout 30m -v "$@" {{ pkg }}...

# Strict Linux compatibility: no skips, egress audit required.
#
# It takes arguments like the others and does not have to trust them. The
# preflight in main_test.go refuses -run, -skip, -short, -bench, -fuzz and
# -list by name before a single row runs, so a narrowed strict run cannot be
# mistaken for a strict gate.
[doc('Run the strict profile; container, network')]
[group('test')]
test-strict *args:
    @FORGE_CI_BLACKBOX_PROFILE=strict go test -tags=blackbox -count=1 -timeout 35m -v "$@" {{ pkg }}...

# For a binary someone else produced: a release artefact, or an engine
# checkout that is not the sibling ../forge-ci the suite builds from.
# The literal path is relative to the recipe working directory (normally this
# checkout), not PATH. Make it absolute before Go changes to the test package
# and engine subprocesses change to fixture directories. Keep inherited profile.
[doc('Test binary; container, network; may skip')]
[group('test')]
test-binary binary *args:
    #!/usr/bin/env bash
    set -euo pipefail
    binary=$1
    if [[ ! -f "$binary" || ! -x "$binary" ]]; then
        printf 'test-binary: expected an executable file, got %q; use an absolute path or one relative to the recipe working directory\n' "$binary" >&2
        exit 2
    fi
    if [[ "$binary" != /* ]]; then
        binary="$PWD/$binary"
    fi
    FORGE_CI_TEST_BINARY="$binary" go test -tags=blackbox -count=1 -timeout 30m -v "${@:2}" {{ pkg }}...

# One row, or a family of them, by name: the loop once a failure is located.
# Verbose already, because a single black-box row is worth reading in full.
#
#   just test-run TestFlow_ContainerFirst_Go
[doc('Test matching names; container, network')]
[group('test')]
test-run filter *args:
    @go test -tags=blackbox -count=1 -timeout 30m -v -run "$1" "${@:2}" {{ pkg }}

# ==================================================================================== #
# LINT
# ==================================================================================== #

# Justfile format check, gofmt check, go vet and golangci-lint.
[doc('▪ Run the full lint suite')]
[group('lint')]
lint: _check-justfile lint-go-format lint-go-vet lint-go-golangci
    @bash scripts/test-clean-cache.sh

# Report the files that are not gofmt-clean.
[doc('Check Go formatting')]
[group('lint')]
lint-go-format:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted="$(gofmt -l tests/)"
    if [[ -n "$unformatted" ]]; then
        printf "{{ RED }}✗ not gofmt-clean:{{ NC }}\n%s\n" "$unformatted" >&2
        printf "  Fix: just lint-fix\n" >&2
        exit 1
    fi

# Run go vet
[group('lint')]
lint-go-vet:
    @go vet -tags=blackbox {{ pkg }}

# Config: .golangci.yml.
[doc('Run golangci-lint')]
[group('lint')]
lint-go-golangci *args: (_require-tool "golangci-lint" "Run with the pinned version: mise exec -- just lint")
    @golangci-lint run "$@" {{ pkg }}

# ==================================================================================== #
# LINT-FIX - Auto-fix linting violations
# ==================================================================================== #

# Justfile formatting, gofmt and golangci-lint --fix.
[doc('▪ Format Just/Go files and apply golangci fixes')]
[group('lint-fix')]
lint-fix: (_require-tool "golangci-lint" "Run with the pinned version: mise exec -- just lint-fix")
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --fmt
    @gofmt -w tests/
    @golangci-lint run --fix {{ pkg }}

# Format Go and tidy go.mod
[group('lint-fix')]
tidy:
    @gofmt -w tests/
    @go mod tidy

# ==================================================================================== #
# MAINTENANCE
# ==================================================================================== #

# The cached toolchain home and buildah store are both caches.
[doc('▪ Remove the suite caches and Go test cache')]
[group('maintenance')]
clean:
    @bash {{ quote(justfile_directory() / "scripts/clean-cache.sh") }}
    @go clean -testcache

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

# Fail before the Go checks when the justfile needs formatting.
[private]
_check-justfile:
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --fmt --check

# Fail with an install hint when a required tool is missing.
# Use as a recipe prerequisite: `lint-go-golangci: (_require-tool "golangci-lint" "Install: …")`.
_require-tool tool hint="":
    #!/usr/bin/env bash
    if command -v "$1" >/dev/null 2>&1; then
        exit 0
    fi
    printf "{{ RED }}✗ %s not found{{ NC }}\n" "$1" >&2
    if [[ -n "${2:-}" ]]; then
        printf "  %s\n" "$2" >&2
    fi
    exit 1
