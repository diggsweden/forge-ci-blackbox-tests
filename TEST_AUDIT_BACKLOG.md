<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Black-box test work

This file tracks open work for the Forge CI companion suite. Add reproducible
findings with acceptance criteria; remove them when the fix is verified.

## Current findings

No open test-audit findings are recorded.

## Before the 0.90.0 release

- Run the complete strict suite against the intended Forge CI release binary.
- Confirm the default sibling build and explicit `FORGE_CI_TEST_BINARY` override both select
  the intended engine, with no hidden fallback.
- Retain the resolved engine/suite revisions, bounded test output and artifact
  digests from the compatibility job.
- Review optional toolchain skips in local runs; strict runs must refuse missing
  required evidence and disabled egress auditing.
