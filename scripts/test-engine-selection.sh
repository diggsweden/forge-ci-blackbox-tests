#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

# Exercise TestMain's engine selection with a compiled harness and inert tools.
# Called by validate-strict-profile-contract.sh; never builds the real engine.
set -euo pipefail
harness=${1:?pass the absolute path of the compiled blackbox test harness}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
work=$(cd -- "$work" && pwd -P)
mkdir -p "$work/tools" "$work/cache" "$work/renamed source/cmd/forge-ci" "$work/invalid/cmd"
touch "$work/invalid/cmd/forge-ci"
cat >"$work/prebuilt engine" <<'SH'
#!/usr/bin/env bash
printf 'NAME:\n   forge-ci - inert engine selection probe\n'
SH
cat >"$work/tools/go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
work=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
printf '%s\n' "$PWD" >>"$work/build-cwd"
[[ "$#" == 4 && "$1" == build && "$2" == -o && "$4" == ./cmd/forge-ci ]]
[[ ! -f "$work/fail-build" ]] || exit 23
cp "$work/prebuilt engine" "$3"
chmod +x "$3"
SH
chmod +x "$work/tools/go" "$work/prebuilt engine"
export PATH="$work/tools:$PATH" TMPDIR="$work/cache" HOME="$work"
unset FORGE_CI_BLACKBOX_PROFILE FORGE_CI_TEST_BINARY FORGE_CI_TEST_SOURCE
fail() {
	printf 'engine selection contract: %s\n' "$1" >&2
	cat "$work/output" >&2
	exit 1
}
run() { "$harness" -test.run='^TestBinaryIdentity_HelpNamesForgeCI$' >"$work/output" 2>&1; }

# No discovery, relative source paths or non-directory command paths.
for source in '' relative "$work/missing" "$work/invalid"; do
	status=0
	FORGE_CI_TEST_SOURCE="$source" run || status=$?
	[[ "$status" == 2 ]] || fail "invalid source accepted: $source"
	[[ $(<"$work/output") == *FORGE_CI_TEST_SOURCE* ]] || fail 'missing selection guidance'
	[[ ! -e "$work/build-cwd" ]] || fail 'invalid source reached the compiler'
done

# A prebuilt binary wins even over an invalid source input.
FORGE_CI_TEST_BINARY="$work/prebuilt engine" FORGE_CI_TEST_SOURCE="$work/missing" run || fail 'prebuilt selection failed'
[[ ! -e "$work/build-cwd" ]] || fail 'source build overrode explicit binary'

# A renamed checkout with spaces is built exactly once, at the selected path.
FORGE_CI_TEST_SOURCE="$work/renamed source" run || fail 'explicit source build failed'
[[ $(<"$work/build-cwd") == "$work/renamed source" ]] || fail 'wrong source directory or repeated build'

# A failed build must not fall back to a different engine.
touch "$work/fail-build"
if FORGE_CI_TEST_SOURCE="$work/renamed source" run; then
	fail 'failed source build passed'
fi
[[ $(<"$work/output") == *'build forge-ci: exit status 23'* ]] || fail 'build failure was hidden'
printf 'engine selection contract: explicit source, binary precedence, refusal and build failure passed\n'
