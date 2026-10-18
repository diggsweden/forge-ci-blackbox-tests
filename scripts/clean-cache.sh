#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0
set -euo pipefail
(($# == 0)) || {
  printf 'Usage: clean-cache.sh (the cache root follows TMPDIR on Linux, HOME on macOS).\n' >&2
  exit 2
}
admit_directory() {
  local path=$1 writable
  [[ -e "$path" || -L "$path" ]] || return 0
  if [[ -L "$path" || ! -d "$path" || ! -O "$path" ]]; then
    printf 'Refusing unowned or linked cache directory: %q\n' "$path" >&2
    exit 2
  fi
  writable=$(find "$path" -prune \( -perm -020 -o -perm -002 \) -print) || exit 1
  if [[ -n "$writable" ]]; then
    printf 'Refusing group- or world-writable cache directory: %q\n' "$path" >&2
    exit 2
  fi
}
# The suite's cacheRoot (tests/blackbox/helpers_test.go) derives the same root.
# macOS purges old files under TMPDIR, so the caches live in the user cache
# directory there; that root belongs to the suite and is admitted like a cache.
if [[ $OSTYPE == darwin* ]]; then
  [[ ${HOME:-} == /* ]] || {
    printf 'HOME must be absolute.\n' >&2
    exit 2
  }
  root="$HOME/Library/Caches/forge-ci-blackbox-tests"
  [[ -e "$root" || -L "$root" ]] || exit 0
  admit_directory "$root"
else
  root=${TMPDIR:-/tmp}
  [[ "$root" == /* ]] || {
    printf 'TMPDIR must be absolute.\n' >&2
    exit 2
  }
fi
readonly root
# One fixed target list is shared by admission, permission repair and removal.
# This entry point accepts no caller-supplied deletion paths.
readonly -a cache_paths=(
  "$root/forge-ci-blackbox-home"
  "$root/forge-ci-blackbox-buildah"
)
lock="$root/forge-ci-blackbox.lock"
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
for path in "${cache_paths[@]}"; do
  admit_directory "$path"
done
buildah_home=${cache_paths[1]}
admit_directory "$buildah_home/storage"
admit_directory "$buildah_home/run"
if [[ -d "$buildah_home/storage" ]]; then
  command -v buildah >/dev/null 2>&1 || {
    printf 'Buildah is required to clean its image store; use the Linux environment that created it.\n' >&2
    exit 2
  }
  # Interrupted cleanup may have removed HOME before the image store. Create
  # the missing private home exclusively before the runtime can read config.
  if [[ -e "${cache_paths[0]}" || -L "${cache_paths[0]}" ]]; then
    admit_directory "${cache_paths[0]}"
  else
    mkdir -m 0700 -- "${cache_paths[0]}"
  fi
  # Buildah owns removal of UID-mapped image layers. The same private roots
  # as the suite prevent these operations from reaching the user's store.
  # A closed environment also excludes ambient container configuration.
  for command in rm rmi; do
    env -i PATH="$PATH" HOME="${cache_paths[0]}" \
      buildah --root "$buildah_home/storage" --runroot "$buildah_home/run" "$command" --all
  done
fi
# Go's module cache has read-only directories. Restore owner write permission
# only on real directories inside the admitted caches; never follow links.
for path in "${cache_paths[@]}"; do
  [[ -d "$path" ]] || continue
  find "$path" -type d -exec chmod u+w {} +
done
rm -rf -- "${cache_paths[@]}"
