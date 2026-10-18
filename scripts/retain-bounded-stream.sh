#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: CC0-1.0

set -euo pipefail
export LC_ALL=C

output=${1:?usage: retain-bounded-stream.sh OUTPUT LIMIT_BYTES}
limit=${2:?usage: retain-bounded-stream.sh OUTPUT LIMIT_BYTES}
printf -v marker '{"Action":"output","Output":"compatibility evidence truncated at %d bytes\\n"}' "$limit"
payload_limit=$((limit - ${#marker} - 1))
if ((payload_limit < 0)); then
	printf 'stream limit %d is too small for the truncation marker\n' "$limit" >&2
	exit 2
fi

bytes=0
truncated=0
: >"$output"
while IFS= read -r line || [[ -n "$line" ]]; do
	printf '%s\n' "$line"
	if ((truncated)); then
		continue
	fi
	line_bytes=$((${#line} + 1))
	if ((bytes + line_bytes > payload_limit)); then
		printf '%s\n' "$marker" >>"$output"
		truncated=1
		continue
	fi
	printf '%s\n' "$line" >>"$output"
	bytes=$((bytes + line_bytes))
done
