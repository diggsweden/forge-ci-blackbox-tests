<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Host isolation and footprint

## Host isolation

`helpers_test.go::isolatedEnv` wipes the developer's environment for every
binary invocation, then layers the per-test overrides on top:

- `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` keep the
  developer's `~/.gitconfig` (for example `gpg.format=ssh`) from being read,
  which would otherwise break GPG tests silently.
- `HOME` is redirected to the suite's isolated cache home; `LANG=C` and
  `LC_ALL=C` keep human output deterministic.
- `PATH` gains every directory reported by `mise bin-paths`, so toolchains
  installed via mise (node, java, cargo, and so on) work even when
  `mise activate` hasn't run in the calling shell. These discovered mise
  directories precede the host `PATH`; existing duplicate directories are not
  added again.
- A stale `JAVA_HOME` (common after a mise JDK update when the shell still
  points at an old install dir) is detected and dropped, so `mvn` falls back
  to the `java` on PATH.
- Maven keeps the egress auditor's JVM proxy properties even when a test
  overrides `MAVEN_OPTS` to exercise a different `user.home`.
- An explicit `FORGE_CI_PROC_SWAPS` fixture is preserved. Without one, the
  suite supplies its own no-swap fixture; the strict workflow explicitly uses
  `/dev/null`.
- `GIT_AUTHOR_*` and `GIT_COMMITTER_*` are pinned to a stable identity.
- Per-test scratch dirs come from `t.TempDir()`, which Go removes at the end
  of the test.
- For GPG tests, `bootstrapGPGKey` creates a throwaway ed25519 key in an
  isolated `GNUPGHOME` with ultimate ownertrust, so signing works without
  prompts. `bootstrapRSAGPGKey` makes an RSA-2048 key instead;
  `TestReleaseSign_GPGSignsAndVerifies` uses it so RSA signing stays covered.
- For SSH tests, `bootstrapSSHKey` generates a fresh ed25519 keypair plus an
  `allowed_signers` file.

## Host footprint

The suite publishes nothing and does not touch your git config, GPG keys, or
credentials. The `publish` tests only exercise the local validation verbs
(write an `.npmrc` to a temp file, check a tarball, walk a `target/` tree);
the real deploy verbs are never called. Forge APIs are faked, and
`container login` writes to a temp authfile.

Toolchain and container caches are redirected out of your real home so a run
leaves it untouched, while the caches still persist between runs so a warm
rerun stays fast:

- Real toolchain runs (mvn, gradle, cargo, npm, go) get a dedicated `$HOME` at
  `$TMPDIR/forge-ci-blackbox-home`. Their caches land there (`~/.m2`,
  `~/.gradle`, `~/.cargo`, `~/.npm`, the go build and module cache), not in
  your own home. The JVM ignores `$HOME` for `user.home`, so Maven receives an
  explicit private `settings.xml` and local repository through `MAVEN_ARGS`,
  while Gradle receives `GRADLE_USER_HOME`. Maven never reads your real
  `~/.m2/settings.xml`, credentials, mirrors, or forge endpoints.
- The buildah tests build into a dedicated store at
  `$TMPDIR/forge-ci-blackbox-buildah`, not your default container storage, so
  test images never appear in `buildah images`.

Both locations may fetch public package/tool inputs over the network on a cold
cache (dependencies, Maven plugins, the Gradle distribution, base images).
They are pure caches and never carry real credentials or user settings. Use
`just clean` to reclaim them.

## The cache lock

The suite and cleanup both acquire `$TMPDIR/forge-ci-blackbox.lock` (`/tmp`
when `TMPDIR` is unset); another owner is refused before the shared caches are
used or removed. Cleanup also refuses linked directories or caches owned by
another user. `TMPDIR` must be absolute.

Tests within one suite retain their existing parallel/serial policy; separate
suites sharing a temp root run sequentially.

The lock regression runs in the Go suite. Its shell-only cleanup counterpart is
`bash scripts/test-clean-cache.sh`; it uses disposable directories and starts
no engine, container, or network operation.

## Stopping a run

Ctrl-C, `SIGTERM` or `SIGHUP` stops the suite within seconds. The binaries
under test run in process groups of their own, which a terminal's Ctrl-C does
not reach, so the suite kills each running group itself, as it does on a
timeout. The remaining tests fail as interrupted, and a second Ctrl-C ends the
run at once.

An interrupted run keeps the lock, because its children stopped mid-write, and
prints the command to start clean: confirm that no suite or cleanup is still
using these caches, then `rmdir` the lock and run `just clean`. A killed
process leaves the lock too. It is never reclaimed automatically.
