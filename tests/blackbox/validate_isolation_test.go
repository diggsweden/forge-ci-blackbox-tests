// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `validate isolation`, which performs selected static
// release-isolation checks. No job may reach a signing secret but the
// prepare job, the sign job and a call of one of the layer's signer
// workflows, and every actions/checkout must set persist-credentials: false. This is
// pure static YAML analysis, so the fixtures are tiny inline workflows.
// All output (the pass line and the violation annotations) goes to
// stderr; assertions target message substrings, which are identical
// across the GitHub and Forgejo annotation formats.

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempWorkflow writes body to a .yml file in a fresh temp dir and
// returns its path. Shared by the workflow-analysing validate tests.
func writeTempWorkflow(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "workflow.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	return path
}

// TestIsolation_CleanWorkflowPasses: a job with no signing secrets
// and a credential-less checkout satisfies the gate.
func TestIsolation_CleanWorkflowPasses(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - run: make dist
`)

	_, stderr, code := run(t, runOpts{}, "validate", "isolation", "--workflow", wf)

	if code != 0 {
		t.Fatalf("expected exit 0 for clean workflow, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "isolation pass", stderr, "Static release-isolation checks passed")
}

// TestIsolation_BuildJobSecretFails: a signing secret referenced in the
// build job, which runs the project's code, breaks release isolation.
func TestIsolation_BuildJobSecretFails(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
    env:
      KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
`)

	_, stderr, code := run(t, runOpts{}, "validate", "isolation", "--workflow", wf)

	if code != exitValidation { // EX_VALIDATION: isolation broken
		t.Fatalf("expected EX_VALIDATION=1 for leaked secret, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "secret leak", stderr, "references signing secret")
	assertContains(t, "secret leak", stderr, "never a job that runs the project's code")
}

// TestIsolation_FindsASecretWhereverItHides pins the REACH of the scan, which
// the test above does not: it places its secret in the build job's `env`, so a
// scanner narrowed to that one location or job would keep it green while
// missing every other way a key reaches the project's code.
//
// A key can be interpolated into a `run:` script, passed through step-level
// env, inherited from the workflow env or given to any other job, so the scan
// must walk every scalar of every job rather than fixed keys.
//
// Names come from the default --signing-secret list (RELEASE_GPG_PRIVATE_KEY,
// RELEASE_GPG_PASSPHRASE, COSIGN_PRIVATE_KEY, COSIGN_PASSWORD). That list is
// the deliberate policy boundary — not every `secrets.*` is a signing key, and
// a build job legitimately holds registry tokens — so this test varies the
// LOCATION and holds the name listed, which is the half the scanner owns.
func TestIsolation_FindsASecretWhereverItHides(t *testing.T) {
	t.Parallel()

	const (
		head = `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
`
		checkout = `    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
`
	)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"job level env", head + `    env:
      KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
` + checkout},

		{"step level env", head + checkout + `      - run: make dist
        env:
          KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
`},

		// The one that matters most: a key echoed into a shell script never
		// appears as a YAML key at all, only inside a scalar.
		{"interpolated into a run body", head + checkout + `      - run: echo "${{ secrets.RELEASE_GPG_PRIVATE_KEY }}" | gpg --import
`},

		{"passed as a with input", head + checkout + `      - uses: ./.github/actions/sign
        with:
          key: ${{ secrets.COSIGN_PRIVATE_KEY }}
`},

		{"inherited from the workflow env", `env:
  KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
` + head + checkout},

		{"given to a job other than the build", head + checkout + `  test:
    runs-on: ubuntu-24.04
    env:
      KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
    steps: []
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, runOpts{}, "validate", "isolation",
				"--workflow", writeTempWorkflow(t, tc.body))

			if code != exitValidation {
				t.Errorf("a signing secret in the %s was not flagged: exit %d\nstderr: %s", tc.name, code, stderr)
			}

			assertContains(t, tc.name, stderr, "never a job that runs the project's code")
		})
	}

	// The boundary in the other direction: a call of one of the layer's
	// signer workflows is where these secrets belong, so a secret there must
	// not be flagged. Without this, a scanner that flagged every reference
	// would satisfy every case above while making the gate unusable.
	_, stderr, code := run(t, runOpts{}, "validate", "isolation",
		"--workflow", writeTempWorkflow(t, head+checkout+`  sign:
    uses: examplescope/ci-layer/.forgejo/workflows/sign-container-images.yml@1111111111111111111111111111111111111111
    secrets:
      COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
`))
	if code != 0 {
		t.Errorf("a signing secret passed to a signer workflow call was flagged: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "secret in the signer call", stderr, "Static release-isolation checks passed")
}

// TestIsolation_PersistCredentialsFails: a checkout that doesn't disable
// credential persistence leaves the token on disk for later steps.
func TestIsolation_PersistCredentialsFails(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
`)

	_, stderr, code := run(t, runOpts{}, "validate", "isolation", "--workflow", wf)

	if code != exitValidation { // EX_VALIDATION: isolation broken
		t.Fatalf("expected EX_VALIDATION=1 for persisted credentials, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "persist-credentials", stderr, "persist-credentials: false")

	// The other spelling of the same mistake. Omitting the key and setting it
	// to true are different YAML shapes, and a check that only noticed the
	// missing key would pass the explicit one — which is the spelling someone
	// arrives at by deliberately turning it back on.
	explicit := writeTempWorkflow(t, `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: true
`)

	if _, stderr, code = run(t, runOpts{}, "validate", "isolation", "--workflow", explicit); code != exitValidation {
		t.Errorf("explicit persist-credentials: true was not flagged: exit %d\nstderr: %s", code, stderr)
	}
}

// TestIsolation_MissingWorkflowFlagIsUsageError: --workflow is required;
// omitting it is a caller mistake (EX_USAGE), not a validation failure.
func TestIsolation_MissingWorkflowFlagIsUsageError(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{}, "validate", "isolation")

	if code != exitUsage { // EX_USAGE: required flag missing
		t.Fatalf("expected EX_USAGE=2 when --workflow omitted, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "usage", stderr, `Required flag "workflow" not set`)
}

// TestIsolation_MissingSignJobIsRefused: a --sign-job that names no job in
// the workflow must not pass vacuously. A renamed job would otherwise turn the
// signing checks into a check of nothing.
func TestIsolation_MissingSignJobIsRefused(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `name: release
jobs:
  release:
    uses: examplescope/ci-layer/.forgejo/workflows/sign-and-publish-release.yml@1111111111111111111111111111111111111111
`)

	_, stderr, code := run(t, runOpts{}, "validate", "isolation", "--workflow", wf, "--sign-job", "sign")

	if code != exitValidation {
		t.Fatalf("a sign job the workflow does not have was accepted: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "missing sign job", stderr, `sign job "sign" is missing from workflow`)
}

// TestIsolation_PrepareCallPassesTheSignersSecrets: prepare-release.yml
// refuses a release before its tag when a secret the release uses is not
// configured, and sees only what its caller passes, so the gate refuses a
// prepare call without a secret the sign job takes.
func TestIsolation_PrepareCallPassesTheSignersSecrets(t *testing.T) {
	t.Parallel()

	const pin = "1111111111111111111111111111111111111111"

	workflow := func(prepareSecrets string) string {
		return `jobs:
  prepare:
    uses: examplescope/ci-layer/.forgejo/workflows/prepare-release.yml@` + pin + `
` + prepareSecrets + `  build-and-release:
    outputs:
      dist-digest: ${{ steps.handoff.outputs.digest }}
    steps: []
  sign-and-publish:
    uses: examplescope/ci-layer/.forgejo/workflows/sign-and-publish-release.yml@` + pin + `
    with:
      release-tag: ${{ needs.prepare.outputs.release-tag }}
      release-sha: ${{ needs.prepare.outputs.release-sha }}
      artifacts-config: ${{ needs.prepare.outputs.artifacts-config }}
      dist-digest: ${{ needs.build-and-release.outputs.dist-digest }}
    secrets:
      GPG_SIGNING_KEY: ${{ secrets.GPG_SIGNING_KEY }}
`
	}

	for _, test := range []struct {
		name, secrets string
		want          int
	}{
		{"passed", "    secrets:\n      GPG_SIGNING_KEY: ${{ secrets.GPG_SIGNING_KEY }}\n", 0},
		{"inherited", "    secrets: inherit\n", 0},
		{"left out", "", exitValidation},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			wf := writeTempWorkflow(t, workflow(test.secrets))

			_, stderr, code := run(t, runOpts{}, "validate", "isolation", "--workflow", wf,
				"--sign-job", "sign-and-publish", "--prepare-job", "prepare",
				"--dist-digest-output", "dist-digest", "--signing-secret", "GPG_SIGNING_KEY")
			if code != test.want {
				t.Fatalf("exit %d, expected %d\nstderr: %s", code, test.want, stderr)
			}

			if test.want != 0 {
				assertContains(t, "prepare secrets", stderr, `prepare job "prepare" call site is missing secret GPG_SIGNING_KEY`)
			}
		})
	}
}
