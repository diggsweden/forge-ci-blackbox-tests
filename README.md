<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# forge-ci-blackbox-tests

The black-box test suite for [Forge CI](https://github.com/diggsweden/forge-ci).
It runs the real `forge-ci` binary against small per-ecosystem fixtures and
real toolchains, and checks what comes out: files, exit codes, JSON, and
signatures you can verify with `sha256sum --check` or `gpg --verify`.

- Catches what unit tests cannot: real toolchain failures, non-reproducible
  output, and a developer's own settings leaking into a result.
- Leaves your home directory, Git config, keys and credentials alone.

## Quick Start

Check out this repository next to `forge-ci`; the suite builds the engine from
`../forge-ci`:

Install and activate [mise](https://mise.jdx.dev/getting-started.html) first.

```bash
git clone https://github.com/diggsweden/forge-ci.git
git clone https://github.com/diggsweden/forge-ci-blackbox-tests.git
cd forge-ci-blackbox-tests
mise trust
mise install just
mise exec -- just install-dev-tools
```

Then run the suite:

```bash
# Local run: tests whose tools are missing skip, and are listed as NOT PROVEN
just test

# The strict CI profile: every skip fails instead
just test-strict

# One test, or a pattern
just test-run TestFlow_ContainerFirst_Go

# A binary you built yourself instead of ../forge-ci
just test-binary /path/to/forge-ci
```

A run may download dependencies and base images, and may start containers.
Caches go under `$TMPDIR` (`~/Library/Caches/forge-ci-blackbox-tests` on
macOS) and persist between runs; `just clean` removes them.

A passing local run can still contain **NOT PROVEN** scenarios. Use
`test-strict` on Linux when you need complete compatibility evidence.
After interruption, follow the printed lock-recovery command before cleaning;
see [Stopping a run](docs/isolation.md#stopping-a-run).

Linux is the reference platform and the only one the strict profile accepts.
The local profile also runs natively on macOS, matching forge-ci's Linux and
macOS release targets; WSL is best effort.

## Using the suite

- **[Scope](docs/scope.md)** • Why the suite exists, which tier it is, what it
  leaves out, and what is tested where
- **[Running](docs/running.md)** • Requirements, choosing the engine, profiles,
  `just` recipes, and common problems
- **[Host isolation and footprint](docs/isolation.md)** • What a run changes on
  your machine, the cache lock, and stopping a run
- **[Release shapes](docs/release-shapes.md)** • Artifact-first,
  container-first and container-packaging, and which tests cover each
- **[CI](docs/ci.md)** • The compatibility workflow, its triggers, and the
  evidence bundle it keeps

## Working on the suite

- **[Development](docs/development.md)** • Adding a test, the helpers, and lint
- **[Layout](docs/layout.md)** • The repository layout and where a test goes
- **[Open work](TEST_AUDIT_BACKLOG.md)** • Known findings waiting for a fix
- **[Issues](https://github.com/diggsweden/forge-ci-blackbox-tests/issues)** •
  Report bugs or request coverage

## License

Code is licensed `EUPL-1.2 OR GPL-3.0-or-later`; documentation, configuration
and fixtures are CC0-1.0. The vendored Gradle wrapper keeps its Apache-2.0
licence. Full license texts are in [`LICENSES/`](LICENSES/).
