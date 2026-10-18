#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

set -euo pipefail

evidence_dir=${1:?usage: bound-evidence-bundle.sh EVIDENCE_DIR [ARTIFACT_LIMIT_BYTES]}
artifact_limit=${2:-15728640}
seal_reserve=131072
bundle_target=$artifact_limit
if ((artifact_limit > seal_reserve)); then
	bundle_target=$((artifact_limit - seal_reserve))
fi

install -d -m 0700 "$evidence_dir"
record="$evidence_dir/evidence-truncations.txt"
rm -f "$record"

record_omission() {
	local kind=$1 file=$2 original=$3 limit=$4
	printf 'kind=%s file=%s original_bytes=%s limit_bytes=%s disposition=omitted\n' \
		"$kind" "$(basename "$file")" "$original" "$limit" >>"$record"
}

omit_above_limit() {
	local name=$1 limit=$2
	local file="$evidence_dir/$name"
	[[ -f "$file" ]] || return 0
	local size
	size=$(stat -c '%s' "$file")
	if ((size > limit)); then
		record_omission per-file-limit "$file" "$size" "$limit"
		rm -f -- "$file"
	fi
}

# The event stream and source manifests have externally documented limits.
# Smaller auxiliary caps leave room for sealing metadata and SHA256SUMS.
omit_above_limit strict-blackbox.jsonl 10485760
omit_above_limit forge-ci.sources.sha256 2097152
omit_above_limit companion.sources.sha256 2097152
omit_above_limit resolved-container-images.json 131072
omit_above_limit resolved-container-images.error.txt 65536
omit_above_limit tool-versions.json 65536
omit_above_limit exercised-scenarios.txt 65536
omit_above_limit exercised-command-groups.txt 65536
omit_above_limit metadata.txt 65536

bundle_size() {
	du -sb "$evidence_dir" | cut -f1
}

# Per-file-valid evidence can still exceed the aggregate cap. Omit lower-value
# companions first and retain a bounded explanation instead of losing upload of
# the entire bundle.
for name in \
	resolved-container-images.json \
	resolved-container-images.error.txt \
	companion.sources.sha256 \
	forge-ci.sources.sha256 \
	tool-versions.json \
	exercised-command-groups.txt \
	exercised-scenarios.txt \
	metadata.txt \
	strict-blackbox.jsonl; do
	size=$(bundle_size)
	((size <= bundle_target)) && break
	file="$evidence_dir/$name"
	[[ -f "$file" ]] || continue
	original=$(stat -c '%s' "$file")
	record_omission aggregate-limit "$file" "$original" "$bundle_target"
	rm -f -- "$file"
done

if [[ -f "$record" && ! -s "$record" ]]; then
	rm -f "$record"
fi

size=$(bundle_size)
if ((size > bundle_target)); then
	printf 'evidence bundle remains %d bytes after bounding; target is %d bytes\n' "$size" "$bundle_target" >&2
	exit 1
fi
