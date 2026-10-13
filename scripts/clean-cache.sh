#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0
set -euo pipefail
(($# == 0)) || {
  printf 'Usage: clean-cache.sh (select the temporary root through TMPDIR).\n' >&2
  exit 2
}
temporary=${TMPDIR:-/tmp}
[[ "$temporary" == /* ]] || {
  printf 'TMPDIR must be absolute.\n' >&2
  exit 2
}
lock="$temporary/forge-ci-blackbox.lock"
mkdir -m 0700 -- "$lock" || {
  printf 'Suite or cleanup active, or prior run interrupted; inspect %q.\n' "$lock" >&2
  exit 2
}
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ! rmdir -- "$lock"; then ((status != 0)) || status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for name in forge-ci-blackbox-home forge-ci-blackbox-buildah; do
  path="$temporary/$name"
  [[ -e "$path" || -L "$path" ]] || continue
  if [[ -L "$path" || ! -d "$path" || ! -O "$path" ]]; then
    printf 'Refusing unowned or linked cache directory: %q\n' "$path" >&2
    exit 2
  fi
done
rm -rf -- "$temporary/forge-ci-blackbox-home" "$temporary/forge-ci-blackbox-buildah"
