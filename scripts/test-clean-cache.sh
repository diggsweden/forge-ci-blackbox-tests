#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d)
trap 'chmod -R u+w "$work"; rm -rf -- "$work"' EXIT
# The script derives the cache root from TMPDIR on Linux and from HOME on
# macOS; every run below sets both to one base.
cache="$work/base"
[[ $OSTYPE != darwin* ]] || cache="$work/base/Library/Caches/forge-ci-blackbox-tests"
mkdir -p "$cache" "$work/outside"
mkdir "$cache/forge-ci-blackbox-home" "$cache/forge-ci-blackbox-buildah"
printf keep >"$cache/forge-ci-blackbox-home/canary"
printf keep >"$work/outside/canary"
status=0
TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" --all >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$cache/forge-ci-blackbox-home/canary" && ! -e "$cache/forge-ci-blackbox.lock" ]]
mkdir "$cache/forge-ci-blackbox.lock"
status=0
TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$cache/forge-ci-blackbox-home/canary" && -d "$cache/forge-ci-blackbox.lock" ]]
rmdir "$cache/forge-ci-blackbox.lock" "$cache/forge-ci-blackbox-buildah"
ln -s "$work/outside" "$cache/forge-ci-blackbox-buildah"
status=0
TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$cache/forge-ci-blackbox-home/canary" && -f "$work/outside/canary" ]]
[[ ! -e "$cache/forge-ci-blackbox.lock" ]]
rm "$cache/forge-ci-blackbox-buildah"
mkdir -m 0777 "$cache/forge-ci-blackbox-buildah"
chmod 0500 "$cache/forge-ci-blackbox-home"
status=0
TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$cache/forge-ci-blackbox-home/canary" ]]
[[ $(<"$work/log") == *'group- or world-writable'* ]]
[[ $(LC_ALL=C ls -ld "$cache/forge-ci-blackbox-home") == dr-x------* ]]
[[ ! -e "$cache/forge-ci-blackbox.lock" ]]
chmod 0700 "$cache/forge-ci-blackbox-home"
rmdir "$cache/forge-ci-blackbox-buildah"
mkdir -p "$cache/forge-ci-blackbox-home/go/pkg/mod/fixture"
printf module >"$cache/forge-ci-blackbox-home/go/pkg/mod/fixture/source.go"
chmod 0555 "$cache/forge-ci-blackbox-home/go/pkg/mod/fixture"
ln -s "$work/outside" "$cache/forge-ci-blackbox-home/external"
chmod 0500 "$work/outside"
# The configured temp root may itself use a system-style symlinked parent.
ln -s "$work/base" "$work/base-alias"
TMPDIR="$work/base-alias/" HOME="$work/base-alias/" bash "$root/scripts/clean-cache.sh"
[[ ! -e "$cache/forge-ci-blackbox-home" && ! -e "$cache/forge-ci-blackbox.lock" && -f "$work/outside/canary" ]]
[[ $(LC_ALL=C ls -ld "$work/outside") == dr-x------* ]]
# Container cleanup must stay scoped to the owned store and stop before host
# deletion if the runtime cannot remove its UID-mapped layers.
mkdir -p "$work/tools" "$cache/forge-ci-blackbox-home" "$cache/forge-ci-blackbox-buildah/storage"
chmod 0700 "$cache/forge-ci-blackbox-home"
printf keep >"$cache/forge-ci-blackbox-home/canary"
cat >"$work/tools/buildah" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 6 && $1 == --root && $3 == --runroot && $6 == --all ]]
root=${2%/forge-ci-blackbox-buildah/storage}
[[ $2 == "$root/forge-ci-blackbox-buildah/storage" && $4 == "$root/forge-ci-blackbox-buildah/run" ]]
[[ $HOME == "$root/forge-ci-blackbox-home" && -z ${PROBE_CANARY:-} ]]
[[ -d $HOME && $(LC_ALL=C ls -ld "$HOME") == drwx------* ]]
[[ $5 == rm || $5 == rmi ]]
printf '%s\n' "$5" >>"$root/runtime-calls"
[[ ! -f "$root/runtime-failure" ]] || exit 42
SH
chmod 0700 "$work/tools/buildah"
touch "$cache/runtime-failure"
status=0
TMPDIR="$work/base" HOME="$work/base" PATH="$work/tools:$PATH" PROBE_CANARY=private \
	bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ $status == 42 && -f "$cache/forge-ci-blackbox-home/canary" ]]
[[ -d "$cache/forge-ci-blackbox-buildah/storage" && ! -e "$cache/forge-ci-blackbox.lock" ]]
rm "$cache/runtime-failure" "$cache/runtime-calls"
ln -s "$work/outside" "$cache/forge-ci-blackbox-buildah/run"
status=0
TMPDIR="$work/base" HOME="$work/base" PATH="$work/tools:$PATH" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ $status == 2 && ! -e "$cache/runtime-calls" && -f "$work/outside/canary" ]]
rm "$cache/forge-ci-blackbox-buildah/run"
rm "$cache/forge-ci-blackbox-home/canary"
rmdir "$cache/forge-ci-blackbox-home"
TMPDIR="$work/base" HOME="$work/base" PATH="$work/tools:$PATH" PROBE_CANARY=private bash "$root/scripts/clean-cache.sh"
[[ $(<"$cache/runtime-calls") == $'rm\nrmi' ]]
[[ ! -e "$cache/forge-ci-blackbox-home" && ! -e "$cache/forge-ci-blackbox-buildah" ]]
if [[ $OSTYPE == darwin* ]]; then
	# The macOS root belongs to the suite: absent means nothing to clean, and a
	# linked or shared root is refused before the lock is taken inside it.
	rm -r -- "$cache"
	TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh"
	[[ ! -e "$cache" ]]
	mkdir -p "$work/elsewhere/forge-ci-blackbox-home"
	ln -s "$work/elsewhere" "$cache"
	status=0
	TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
	[[ $status == 2 && -d "$work/elsewhere/forge-ci-blackbox-home" && ! -e "$work/elsewhere/forge-ci-blackbox.lock" ]]
	rm "$cache"
	mkdir -m 0777 "$cache"
	status=0
	TMPDIR="$work/base" HOME="$work/base" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
	[[ $status == 2 && $(<"$work/log") == *'group- or world-writable'* && ! -e "$cache/forge-ci-blackbox.lock" ]]
fi
printf 'Companion cache cleanup contracts passed.\n'
