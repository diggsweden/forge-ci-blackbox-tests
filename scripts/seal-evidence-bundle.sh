#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0
# Seals a bounded evidence bundle: writes SHA256SUMS over its files, makes
# them read-only, and checks the sealed bundle still fits the upload limit.
# Called by the integration workflow and validate-strict-profile-contract.sh.
# Usage: seal-evidence-bundle.sh EVIDENCE_DIR ARTIFACT_LIMIT_BYTES

set -euo pipefail

evidence_dir=${1:?usage: seal-evidence-bundle.sh EVIDENCE_DIR ARTIFACT_LIMIT_BYTES}
artifact_limit=${2:?usage: seal-evidence-bundle.sh EVIDENCE_DIR ARTIFACT_LIMIT_BYTES}
if [[ ! "$artifact_limit" =~ ^[1-9][0-9]*$ ]] || ! printf -v artifact_limit '%d' "$artifact_limit" 2>/dev/null; then
  printf 'artifact limit must be a positive decimal integer within the shell integer range\n' >&2
  exit 2
fi

(
  cd "$evidence_dir"
  mapfile -d '' files < <(find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z)
  ((${#files[@]} != 0))
  sha256sum -- "${files[@]}" >SHA256SUMS
  chmod 0444 -- "${files[@]}" SHA256SUMS
)

size=$(du -sb "$evidence_dir" | cut -f1)
if ((size > artifact_limit)); then
  printf 'sealed evidence bundle is %d bytes; the upload limit is %d bytes\n' "$size" "$artifact_limit" >&2
  exit 1
fi
