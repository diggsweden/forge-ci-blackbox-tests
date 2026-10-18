#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

# Inert recipe regression: no Go build, engine binary, container or network.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "$root/.justfile-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -- "$work/tools" "$work/other-cwd" "$work/with spaces"

cat >"$work/with spaces/engine" <<'SH'
#!/usr/bin/env bash
printf 'prebuilt probe reached\n'
SH
chmod +x "$work/with spaces/engine"
cat >"$work/tools/go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" >"$PROBE_WORK/argv"
printf '%s' "${FORGE_CI_BLACKBOX_PROFILE:-}" >"$PROBE_WORK/profile"
[[ "$FORGE_CI_TEST_BINARY" == /* ]] || { printf 'binary path is not absolute\n' >&2; exit 90; }
cd -- "$PROBE_WORK/other-cwd"
"$FORGE_CI_TEST_BINARY"
exit "${PROBE_STATUS:-0}"
SH
chmod +x "$work/tools/go"
export PROBE_WORK="$work"
export PATH="$work/tools:$PATH"
unset FORGE_CI_BLACKBOX_PROFILE

run() { just --justfile "$root/justfile" --working-directory "$work" "$@"; }
fail() { printf 'justfile contract: %s\n' "$1" >&2; exit 1; }

# A literal relative file, including spaces, must survive go test's package cwd
# and the engine subprocess's fixture cwd. Argument boundaries must survive too.
run test-binary 'with spaces/engine' -run 'TestOne|Test Two' >"$work/output" 2>&1 || {
	cat "$work/output" >&2
	fail 'relative prebuilt executable did not survive the subprocess cwd'
}
[[ $(<"$work/output") == *'prebuilt probe reached'* ]] || fail 'prebuilt executable was not invoked'
mapfile -d '' -t args <"$work/argv"
[[ ${args[*]} == 'test -tags=blackbox -count=1 -timeout 30m -v -run TestOne|Test Two ./tests/blackbox/...' ]] || fail 'test flags changed'
[[ ${args[7]} == 'TestOne|Test Two' ]] || fail 'filter argument was split'
[[ ! -s "$work/profile" ]] || fail 'default profile was changed'

# Absolute paths and an inherited strict profile must retain their semantics.
FORGE_CI_BLACKBOX_PROFILE=strict run test-binary "$work/with spaces/engine" >"$work/output" 2>&1
[[ $(<"$work/profile") == strict ]] || fail 'strict profile was lost'
status=0
PROBE_STATUS=23 run test-binary "$work/with spaces/engine" >"$work/output" 2>&1 || status=$?
[[ $status == 23 ]] || fail 'go test failure status was lost'

# Refuse bad paths before even starting Go, with a usable remedy.
touch "$work/not-executable"
for input in '' missing not-executable other-cwd; do
	rm -f -- "$work/argv"
	if run test-binary "$input" >"$work/output" 2>&1; then
		fail "invalid binary path was accepted: $input"
	fi
	[[ ! -e "$work/argv" ]] || fail 'Go started before path validation'
	[[ $(<"$work/output") == *'executable file'* ]] || fail 'path refusal lacks guidance'
done
printf 'justfile contract: prebuilt paths, argv, profiles and failure status passed\n'
