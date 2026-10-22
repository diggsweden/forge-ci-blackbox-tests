#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

set -euo pipefail

# The evidence scripts run on the Linux CI runner and use GNU stat/du sizes.
# Refuse BSD utilities up front rather than measuring nothing later.
if ! stat -c '%s' "${BASH_SOURCE[0]}" >/dev/null 2>&1 || ! du -sb "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
	# shellcheck disable=SC2016 # Print the literal command for the operator.
	printf 'blackbox contract: GNU coreutils stat/du required; on macOS: sudo port install coreutils findutils, then PATH="/opt/local/libexec/gnubin:$PATH"\n' >&2
	exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# TestMain takes its cache lock before rejecting an invalid profile. Keep these
# negative probes independent of a running suite and its persistent caches.
export TMPDIR="$tmp"

# The compatibility workflow runs this before the suite; forge-ci's
# workflows ran it at their pinned companion commit. Keep the companion's
# repository/ref overrides available while the parent workflows retain their
# immutable companion pin. A fork may change the literal fallback coordinates
# without changing this contract check.
# Forgejo gives its workflow directory precedence when both provider layers
# are retained. Check the active compatibility file, not the inert GitHub copy.
workflow="$root/.github/workflows/integration.yml"
if [[ -d "$root/.forgejo/workflows" ]]; then
	workflow="$root/.forgejo/workflows/integration.yml"
fi
if [[ ! -f "$workflow" ]]; then
	printf 'blackbox contract: missing compatibility workflow %s\n' "$workflow" >&2
	exit 1
fi
integration=$(<"$workflow")
# shellcheck disable=SC2016 # Match literal workflow expressions, not shell expansions.
for expected in \
	'DEFAULT_REPOSITORY: ${{ vars.FORGE_CI_REPOSITORY || ' \
	'DEFAULT_REF: ${{ vars.FORGE_CI_REF || ' \
	"inputs['forge-ci-ref'] || vars.FORGE_CI_REF || "; do
	if [[ "$integration" != *"$expected"* ]]; then
		printf 'blackbox contract: integration workflow is missing primary-ref guard %s\n' "$expected" >&2
		exit 1
	fi
done
printf 'blackbox contract: companion drift target supports repository/ref overrides\n'

(
	cd "$root"
	go test ./scripts/
	go test -c -tags=blackbox -o "$tmp/blackbox-contract.test" ./tests/blackbox/
)

# Both probes stop in TestMain's preflight, before the suite builds
# forge-ci or runs a row, so they need no toolchain beyond Go.
if FORGE_CI_BLACKBOX_PROFILE=strict \
	"$tmp/blackbox-contract.test" -test.run=TestSelected >"$tmp/negative.log" 2>&1; then
	printf 'blackbox contract: strict profile accepted a selected-test run\n' >&2
	exit 1
fi

negative=$(<"$tmp/negative.log")
if [[ "$negative" != *"forbids test-selection flag"* ]]; then
	printf 'blackbox contract: selected-test probe failed for the wrong reason:\n%s\n' "$negative" >&2
	exit 1
fi

printf 'blackbox contract: selected-test negative probe rejected as required\n'

if BLACKBOX_EGRESS_PROXY=off \
	FORGE_CI_BLACKBOX_PROFILE=strict \
	"$tmp/blackbox-contract.test" >"$tmp/egress-disabled.log" 2>&1; then
	printf 'blackbox contract: strict profile accepted disabled egress auditing\n' >&2
	exit 1
fi

egress_disabled=$(<"$tmp/egress-disabled.log")
if [[ "$egress_disabled" != *"egress audit must run in strict mode"* ]]; then
	printf 'blackbox contract: disabled-egress probe failed for the wrong reason:\n%s\n' "$egress_disabled" >&2
	exit 1
fi

printf 'blackbox contract: disabled egress audit rejected as required\n'

stream="$tmp/evidence-stream"
mkdir -m 0700 "$stream"
stream_seen=$(
	for number in {01..40}; do
		printf 'event-%s-abcdefghijklmnop\n' "$number"
	done | "$root/scripts/retain-bounded-stream.sh" "$stream/strict-blackbox.jsonl" 256
)
stream_size=$(stat -c '%s' "$stream/strict-blackbox.jsonl")
if ((stream_size > 256)); then
	printf 'blackbox contract: retained stream exceeds its byte limit\n' >&2
	exit 1
fi
retained_stream=$(<"$stream/strict-blackbox.jsonl")
if [[ "$retained_stream" != *"compatibility evidence truncated at 256 bytes"* ]]; then
	printf 'blackbox contract: retained stream has no truncation marker\n' >&2
	exit 1
fi
if [[ "$stream_seen" != *"event-40-abcdefghijklmnop"* ]]; then
	printf 'blackbox contract: stream limiter stopped draining after truncation\n' >&2
	exit 1
fi

printf 'blackbox contract: bounded stream drains input and records truncation\n'

per_file="$tmp/evidence-per-file"
mkdir -m 0700 "$per_file"
printf '%s\n' '{"Action":"pass"}' >"$per_file/strict-blackbox.jsonl"
truncate -s 200000 "$per_file/resolved-container-images.json"
"$root/scripts/bound-evidence-bundle.sh" "$per_file" 15728640

if [[ -f "$per_file/resolved-container-images.json" ]]; then
	printf 'blackbox contract: oversized evidence file was retained unbounded\n' >&2
	exit 1
fi
if [[ ! -s "$per_file/evidence-truncations.txt" ]]; then
	printf 'blackbox contract: oversized evidence has no retained truncation record\n' >&2
	exit 1
fi
if [[ ! -s "$per_file/strict-blackbox.jsonl" ]]; then
	printf 'blackbox contract: bounding one evidence file discarded the rest of the bundle\n' >&2
	exit 1
fi
per_file_size=$(du -sb "$per_file" | cut -f1)
if ((per_file_size > 15728640)); then
	printf 'blackbox contract: bounded evidence still exceeds the artifact limit\n' >&2
	exit 1
fi

printf 'blackbox contract: oversized evidence retained a bounded failure record\n'

aggregate="$tmp/evidence-aggregate"
artifact_limit=262144
seal_reserve=131072
bundle_target=$((artifact_limit - seal_reserve))
mkdir -m 0700 "$aggregate"
printf '%s\n' '{"Action":"pass"}' >"$aggregate/strict-blackbox.jsonl"
truncate -s 80000 "$aggregate/companion.sources.sha256"
truncate -s 80000 "$aggregate/forge-ci.sources.sha256"
"$root/scripts/bound-evidence-bundle.sh" "$aggregate" "$artifact_limit"

preseal_size=$(du -sb "$aggregate" | cut -f1)
if ((preseal_size > bundle_target)); then
	printf 'blackbox contract: aggregate bounding did not preserve the sealing reserve\n' >&2
	exit 1
fi
aggregate_record=$(<"$aggregate/evidence-truncations.txt")
if [[ "$aggregate_record" != *"kind=aggregate-limit"* ]]; then
	printf 'blackbox contract: aggregate overflow has no aggregate truncation record\n' >&2
	exit 1
fi
if [[ ! -s "$aggregate/strict-blackbox.jsonl" ]]; then
	printf 'blackbox contract: aggregate bounding discarded the test stream first\n' >&2
	exit 1
fi

printf 'test_step_outcome=success\ncontainer_evidence_step_outcome=success\n' >"$aggregate/evidence-status.txt"
(
	cd "$aggregate"
	mapfile -d '' files < <(find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z)
	((${#files[@]} != 0))
	sha256sum -- "${files[@]}" >SHA256SUMS
	chmod 0444 -- "${files[@]}" SHA256SUMS
	sha256sum --check SHA256SUMS >/dev/null
)

postseal_size=$(du -sb "$aggregate" | cut -f1)
if ((postseal_size <= preseal_size)); then
	printf 'blackbox contract: sealing fixture did not consume any reserved bytes\n' >&2
	exit 1
fi
if ((postseal_size > artifact_limit)); then
	printf 'blackbox contract: post-seal evidence exceeds the upload limit\n' >&2
	exit 1
fi

printf 'blackbox contract: aggregate bounding reserves room for sealing and upload\n'
