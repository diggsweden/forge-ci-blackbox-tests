#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/cache" "$work/outside"
mkdir "$work/cache/forge-ci-blackbox-home" "$work/cache/forge-ci-blackbox-buildah"
printf keep >"$work/cache/forge-ci-blackbox-home/canary"
printf keep >"$work/outside/canary"
status=0
TMPDIR="$work/cache" bash "$root/scripts/clean-cache.sh" --all >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$work/cache/forge-ci-blackbox-home/canary" && ! -e "$work/cache/forge-ci-blackbox.lock" ]]
mkdir "$work/cache/forge-ci-blackbox.lock"
status=0
TMPDIR="$work/cache" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$work/cache/forge-ci-blackbox-home/canary" && -d "$work/cache/forge-ci-blackbox.lock" ]]
rmdir "$work/cache/forge-ci-blackbox.lock" "$work/cache/forge-ci-blackbox-buildah"
ln -s "$work/outside" "$work/cache/forge-ci-blackbox-buildah"
status=0
TMPDIR="$work/cache" bash "$root/scripts/clean-cache.sh" >"$work/log" 2>&1 || status=$?
[[ "$status" == 2 && -f "$work/cache/forge-ci-blackbox-home/canary" && -f "$work/outside/canary" ]]
[[ ! -e "$work/cache/forge-ci-blackbox.lock" ]]
rm "$work/cache/forge-ci-blackbox-buildah"
TMPDIR="$work/cache" bash "$root/scripts/clean-cache.sh"
[[ ! -e "$work/cache/forge-ci-blackbox-home" && ! -e "$work/cache/forge-ci-blackbox.lock" && -f "$work/outside/canary" ]]
printf 'Companion cache cleanup contracts passed.\n'
