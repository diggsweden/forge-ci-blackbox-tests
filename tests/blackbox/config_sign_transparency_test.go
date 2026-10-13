// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// sign.transparency config dimension: whether cosign publishes each
// signature to the public Sigstore transparency log (Rekor).
//
// This is the user-facing front door for the setting the suite itself relies on
// for containment (see release_sign_no_tlog_test.go). It matters from the
// outside because a Rekor entry is permanent, public, and append-only: a repo
// that meant "internal only" and got the config subtly wrong cannot take the
// entries back. So the contract worth pinning here is that the incoherent
// combinations are refused at config time, with an exit code a pipeline can
// gate on — not deep inside cosign at release time.
package blackbox

import (
	"testing"
)

// signPlan is the decoded sign block, including the fields a caller's egress
// allowlist reads.
type signPlan struct {
	Method                 string `json:"method"`
	Transparency           string `json:"transparency"`
	RequiresSigstoreEgress bool   `json:"requires_sigstore_egress"`
}

// parseSignPlan returns the sign block of the config plan for repo.
func parseSignPlan(t *testing.T, repo string) signPlan {
	t.Helper()

	var plan struct {
		Sign signPlan `json:"sign"`
	}
	decodeJSON(t, "config plan", configPlanJSON(t, repo), &plan)

	return plan.Sign
}

// TestSignTransparency_KMSWithoutALogIsAccepted is the internal-only use case:
// sign with our own long-lived key and publish nothing about it. The signature
// still verifies against the public key — this must not be treated as exotic.
func TestSignTransparency_KMSWithoutALogIsAccepted(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
sign:
  method: kms
  key: hashivault://transit/keys/release
  transparency: none
`)

	_, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
		"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
	}}, "config", "validate")
	if code != 0 {
		t.Fatalf("internal-only signing config rejected: exit %d\nstderr: %s", code, stderr)
	}

	sign := parseSignPlan(t, repo)
	if sign.Transparency != "none" {
		t.Errorf("sign.transparency = %q, want none", sign.Transparency)
	}

	// The payoff: a caller reads this instead of guessing which endpoints to
	// allow. A run that publishes nothing needs no sigstore.dev egress at all.
	if sign.RequiresSigstoreEgress {
		t.Error("sign.requires_sigstore_egress = true for a run that publishes nothing")
	}
}

// TestSignTransparency_DefaultsToPublishing pins the default. Leaving the field
// blank must NOT quietly withhold the public record — opting out is a decision
// someone writes down.
func TestSignTransparency_DefaultsToPublishing(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
sign:
  method: kms
  key: hashivault://transit/keys/release
`)

	sign := parseSignPlan(t, repo)

	if sign.Transparency != "public" {
		t.Errorf("sign.transparency = %q, want public when the field is omitted", sign.Transparency)
	}

	// kms reaches Rekor too — the fact that surprises people, and the reason a
	// hand-written egress allowlist for kms breaks the release when it omits it.
	if !sign.RequiresSigstoreEgress {
		t.Error("sign.requires_sigstore_egress = false for kms publishing to the public log; " +
			"a caller trusting this would block Rekor and fail the signing step at release time")
	}
}

// TestSignTransparency_GPGNeverReachesSigstore pins the other end: the default
// method invokes no cosign at all, so it needs no sigstore.dev egress.
func TestSignTransparency_GPGNeverReachesSigstore(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: go
sign:
  method: gpg
`)

	if sign := parseSignPlan(t, repo); sign.RequiresSigstoreEgress {
		t.Error("sign.requires_sigstore_egress = true for method=gpg, which never runs cosign")
	}
}

// TestSignTransparency_IncoherentConfigsAreRefused pins the combinations that
// must fail at config time.
//
// The sigstore+none case is the one that matters: keyless signs with a
// ~10-minute Fulcio certificate, so without a Rekor inclusion proof the
// signature is unverifiable by anyone, including the repo that made it. Left to
// cosign it surfaces at release time as "not enough verified log entries",
// which names none of its causes.
func TestSignTransparency_IncoherentConfigsAreRefused(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		yaml  string
		wants string
	}{
		{
			name: "sigstore_cannot_skip_the_log",
			yaml: `
artifacts:
  - name: app
    project-type: go
sign:
  method: sigstore
  transparency: none
`,
			// The needle names the field, not just the method: "forbidden for
			// method=sigstore" alone also matches the sign.key rule, so it
			// would stay green if this rule were replaced by a different
			// sigstore refusal.
			wants: "sign.transparency=none is forbidden for method=sigstore",
		},
		{
			name: "gpg_rejects_a_log_it_cannot_publish_to",
			yaml: `
artifacts:
  - name: app
    project-type: go
sign:
  method: gpg
  transparency: none
`,
			// Likewise: three separate gpg rules say "forbidden for
			// method=gpg" (key, oidc-issuer, transparency). Mutation-verified
			// — with the bare method needle, rewriting this rule's message to
			// name sign.key left the test green.
			wants: "sign.transparency is forbidden for method=gpg",
		},
		{
			// The rule is "gpg takes no transparency setting at all", not
			// "gpg takes no opt-out". public is the likelier mistake: it is
			// what a sigstore config carries when it gets copied onto gpg.
			name: "gpg_rejects_a_log_even_when_asked_to_publish",
			yaml: `
artifacts:
  - name: app
    project-type: go
sign:
  method: gpg
  transparency: public
`,
			wants: "sign.transparency is forbidden for method=gpg",
		},
		{
			name: "a_typo_is_not_silently_ignored",
			yaml: `
artifacts:
  - name: app
    project-type: go
sign:
  method: kms
  key: hashivault://transit/keys/release
  transparency: nome
`,
			wants: "is not one of [public, none]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := writeArtifactsRepo(t, tc.yaml)

			_, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
				"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml",
			}}, "config", "validate")

			if code != exitConfig {
				t.Errorf("exit = %d, want %d (EX_CONFIG)\nstderr: %s", code, exitConfig, stderr)
			}

			assertContains(t, "explains the problem", stderr, tc.wants)
		})
	}
}
