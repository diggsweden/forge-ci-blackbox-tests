// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `validate event-context` — the entry guard on
// privileged publish/release workflows. It reads the trigger event from
// --event-name or, when unset, from $EVENT_NAME, then the forge's own
// $FORGEJO_EVENT_NAME / $GITHUB_EVENT_NAME, and refuses
// anything outside the allowlist, most importantly the pull_request
// family, which would otherwise run with the caller's signing/package
// secrets attached to PR-HEAD code. Pure env logic, no fixtures needed.

package blackbox

import "testing"

// TestEventContext_RefusesPullRequest asserts the core guard: a
// pull_request trigger is refused with a validation exit and PR-specific
// guidance. Driven through $FORGEJO_EVENT_NAME to exercise the real
// env-resolution path used in CI.
func TestEventContext_RefusesPullRequest(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{env: map[string]string{"FORGEJO_EVENT_NAME": "pull_request"}},
		"validate", "event-context")

	if code != exitValidation { // EX_VALIDATION: refused trigger
		t.Fatalf("expected EX_VALIDATION=1 for pull_request, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "pull_request refusal", stderr, "is not allowed to run privileged publish/release workflows")
	assertContains(t, "pull_request refusal", stderr, "--allowed-events")
}

// TestEventContext_AllowsPush asserts an allowlisted trigger passes and
// prints the confirmation line.
func TestEventContext_AllowsPush(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{env: map[string]string{"FORGEJO_EVENT_NAME": "push"}},
		"validate", "event-context")

	if code != 0 {
		t.Fatalf("expected exit 0 for push, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "push allowed", stderr, `Trigger event "push" is allowed`)
}

// TestEventContext_AllowlistOverride asserts an adopter can opt a normally
// refused event back in via --allowed-events (the documented escape hatch
// for legitimate preview-deploy flows).
func TestEventContext_AllowlistOverride(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{env: map[string]string{"FORGEJO_EVENT_NAME": "pull_request"}},
		"validate", "event-context", "--allowed-events", "pull_request")

	if code != 0 {
		t.Fatalf("expected exit 0 when pull_request is allowlisted, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "override allowed", stderr, `Trigger event "pull_request" is allowed`)
}

// TestEventContext_EmptyFailsClosed asserts the guard fails closed when no
// event can be resolved at all (EX_NOINPUT), rather than silently
// allowing the run.
func TestEventContext_EmptyFailsClosed(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{}, "validate", "event-context")

	if code != exitNoInput { // EX_NOINPUT: no event resolvable
		t.Fatalf("expected EX_NOINPUT=66 when no event is set, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "empty event", stderr, "trigger event is empty")
}

// TestEventContext_ExplicitEventOutranksTheRunnerVariable pins the source
// order the header states. A workflow that sets EVENT_NAME explicitly is
// describing the event it was written for, and that wins over the runner's
// own variable; the row exists so the order cannot drift unnoticed, since
// either order passes every other test in this file.
func TestEventContext_ExplicitEventOutranksTheRunnerVariable(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{env: map[string]string{
		"EVENT_NAME":        "push",
		"GITHUB_EVENT_NAME": "pull_request",
	}}, "validate", "event-context")

	if code != 0 {
		t.Fatalf("EVENT_NAME=push was outranked by GITHUB_EVENT_NAME: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "explicit event wins", stderr, `Trigger event "push" is allowed`)
}
