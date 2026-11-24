// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `validate isolation`, which performs selected static
// release-isolation checks over a repository's workflow directory. The
// release workflows are found, not named: every workflow with a job that
// calls one of the subject's signer workflows. No job may reach a signing
// secret but such a call, and in the release workflows every actions/checkout
// sets persist-credentials: false, no job passes secrets: inherit, every
// reference is pinned to a full commit and every job image by digest. This is
// pure static YAML analysis, so the fixtures are tiny inline workflows. All
// output (the pass line and the violation annotations) goes to stderr;
// assertions target message substrings, which are identical across the
// GitHub and Forgejo annotation formats.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// isolationSubject is the engine the fixtures call, and isolationPin the
	// one full commit every reference to it uses.
	isolationSubject = "examplescope/ci-layer"
	isolationPin     = "1111111111111111111111111111111111111111"

	// isolationCheckout is a third-party checkout pinned to a full commit,
	// which a job without a secret may run.
	isolationCheckout = `      - uses: actions/checkout@2222222222222222222222222222222222222222
        with:
          persist-credentials: false
`

	// isolationSign calls one of the layer's signer workflows, the one kind
	// of job that may receive a signing key, and makes the workflow a
	// release workflow.
	isolationSign = `  sign:
    needs: build
    uses: examplescope/ci-layer/.forgejo/workflows/sign-container-images.yml@` + isolationPin + `
    with:
      forge-ci-sha: ` + isolationPin + `
    secrets:
      RELEASE_COSIGN_PRIVATE_KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
`

	// isolationBuild is the job that runs the project's code.
	isolationBuild = `name: release
jobs:
  build:
    runs-on: ubuntu-24.04
`
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

// writeWorkflowsDir writes body as the only workflow of a fresh repository
// and returns its workflow directory, two levels below the repository root.
func writeWorkflowsDir(t *testing.T, body string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), ".forgejo", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create workflow directory: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "release.yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	return dir
}

// runIsolation runs the gate over dir for the fixtures' subject.
func runIsolation(t *testing.T, dir string, extra ...string) (string, int) {
	t.Helper()

	args := append([]string{"validate", "isolation", "--workflows-dir", dir, "--single-pin-subject", isolationSubject}, extra...)
	_, stderr, code := run(t, runOpts{}, args...)

	return stderr, code
}

// TestIsolation_CleanWorkflowPasses: a build job with no signing secret and
// a credential-less checkout pinned to a full commit, beside a signer call
// that holds the key, satisfies the gate.
func TestIsolation_CleanWorkflowPasses(t *testing.T) {
	t.Parallel()

	stderr, code := runIsolation(t, writeWorkflowsDir(t, isolationBuild+`    steps:
`+isolationCheckout+`      - run: make dist
`+isolationSign))

	if code != 0 {
		t.Fatalf("expected exit 0 for clean workflow, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "isolation pass", stderr, "Static release-isolation checks passed")
}

// TestIsolation_NoReleaseWorkflowFails: a directory in which no workflow
// calls the subject's signer workflows has nothing to check, and that must
// not pass vacuously: a renamed or moved release workflow would otherwise
// turn the gate into a check of nothing.
func TestIsolation_NoReleaseWorkflowFails(t *testing.T) {
	t.Parallel()

	stderr, code := runIsolation(t, writeWorkflowsDir(t, isolationBuild+`    steps:
`+isolationCheckout))

	if code != exitValidation {
		t.Fatalf("a directory without a release workflow was accepted: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "no release workflow", stderr, "there is no release workflow to check")
}

// TestIsolation_BuildJobSecretFails: a signing secret referenced in the
// build job, which runs the project's code, breaks release isolation.
func TestIsolation_BuildJobSecretFails(t *testing.T) {
	t.Parallel()

	stderr, code := runIsolation(t, writeWorkflowsDir(t, isolationBuild+`    env:
      KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
    steps:
`+isolationCheckout+isolationSign))

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
// env, inherited from the workflow env, given to any other job or written in
// another case, which the forge resolves to the same secret, so the scan must
// walk every scalar of every job rather than fixed keys.
//
// Names come from the default --signing-secret list (RELEASE_COSIGN_* and
// RELEASE_GPG_*). That list is the deliberate policy boundary — not every
// `secrets.*` is a signing key, and a build job legitimately holds read-only
// dependency credentials — so this test varies the LOCATION and holds the
// name listed, which is the half the scanner owns.
func TestIsolation_FindsASecretWhereverItHides(t *testing.T) {
	t.Parallel()

	steps := "    steps:\n" + isolationCheckout

	for _, tc := range []struct {
		name string
		body string
	}{
		{"job level env", isolationBuild + `    env:
      KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
` + steps},

		{"step level env", isolationBuild + steps + `      - run: make dist
        env:
          KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
`},

		// The one that matters most: a key echoed into a shell script never
		// appears as a YAML key at all, only inside a scalar.
		{"interpolated into a run body", isolationBuild + steps + `      - run: echo "${{ secrets.RELEASE_GPG_PRIVATE_KEY }}" | gpg --import
`},

		{"passed as a with input", isolationBuild + steps + `      - uses: example/sign-action@3333333333333333333333333333333333333333
        with:
          key: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
`},

		{"inherited from the workflow env", `env:
  KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
` + isolationBuild + steps},

		{"given to a job other than the build", isolationBuild + steps + `  test:
    runs-on: ubuntu-24.04
    env:
      KEY: ${{ secrets.RELEASE_COSIGN_PRIVATE_KEY }}
    steps: []
`},

		// Forges compare secret names without case, so a lower-case
		// reference reaches the same key.
		{"named in another case", isolationBuild + `    env:
      KEY: ${{ secrets.release_cosign_private_key }}
` + steps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stderr, code := runIsolation(t, writeWorkflowsDir(t, tc.body+isolationSign))
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
	stderr, code := runIsolation(t, writeWorkflowsDir(t, isolationBuild+steps+isolationSign))
	if code != 0 {
		t.Errorf("a signing secret passed to a signer workflow call was flagged: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "secret in the signer call", stderr, "Static release-isolation checks passed")
}

// TestIsolation_PersistCredentialsFails: a checkout that doesn't disable
// credential persistence leaves the token on disk for later steps.
func TestIsolation_PersistCredentialsFails(t *testing.T) {
	t.Parallel()

	missing := isolationBuild + `    steps:
      - uses: actions/checkout@2222222222222222222222222222222222222222
` + isolationSign

	stderr, code := runIsolation(t, writeWorkflowsDir(t, missing))
	if code != exitValidation { // EX_VALIDATION: isolation broken
		t.Fatalf("expected EX_VALIDATION=1 for persisted credentials, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "persist-credentials", stderr, "persist-credentials: false")

	// The other spelling of the same mistake. Omitting the key and setting it
	// to true are different YAML shapes, and a check that only noticed the
	// missing key would pass the explicit one — which is the spelling someone
	// arrives at by deliberately turning it back on.
	explicit := isolationBuild + `    steps:
      - uses: actions/checkout@2222222222222222222222222222222222222222
        with:
          persist-credentials: true
` + isolationSign

	if stderr, code = runIsolation(t, writeWorkflowsDir(t, explicit)); code != exitValidation {
		t.Errorf("explicit persist-credentials: true was not flagged: exit %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "explicit persist-credentials", stderr, "persist-credentials: false")
}

// TestIsolation_RequiredFlagsAreUsageErrors: the workflow directory and the
// subject are both required; leaving either out is a caller mistake
// (EX_USAGE), not a validation failure.
func TestIsolation_RequiredFlagsAreUsageErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no workflow directory", []string{"--single-pin-subject", isolationSubject}, `Required flag "workflows-dir" not set`},
		{"no subject", []string{"--workflows-dir", t.TempDir()}, `Required flag "single-pin-subject" not set`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, stderr, code := run(t, runOpts{}, append([]string{"validate", "isolation"}, tc.args...)...)
			if code != exitUsage { // EX_USAGE: required flag missing
				t.Fatalf("expected EX_USAGE=2, got %d\nstderr: %s", code, stderr)
			}

			assertContains(t, tc.name, stderr, tc.want)
		})
	}
}

// TestIsolation_ReferencesArePinnedToOneFullCommit: a reference to the
// subject at a branch, a tag or a short commit can move under the release,
// and so can a third-party action at a tag. Each one fails.
func TestIsolation_ReferencesArePinnedToOneFullCommit(t *testing.T) {
	t.Parallel()

	subjectAt := func(ref string) string {
		return isolationBuild + "    steps:\n" + isolationCheckout + strings.Replace(isolationSign, ".yml@"+isolationPin, ".yml@"+ref, 1)
	}

	for _, tc := range []struct {
		name, body, want string
	}{
		{"the subject at a branch", subjectAt("main"), "at @main, which is not a full commit"},
		{"the subject at a tag", subjectAt("v1.2.3"), "at @v1.2.3, which is not a full commit"},
		{"the subject at a short commit", subjectAt(isolationPin[:7]), "at @" + isolationPin[:7] + ", which is not a full commit"},
		{
			"a third-party action at a tag",
			isolationBuild + `    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
` + isolationSign,
			"actions/checkout@v5 is neither a path in this repository, nor examplescope/ci-layer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stderr, code := runIsolation(t, writeWorkflowsDir(t, tc.body))
			if code != exitValidation {
				t.Fatalf("%s was accepted: exit %d\nstderr: %s", tc.name, code, stderr)
			}

			assertContains(t, tc.name, stderr, tc.want)
		})
	}
}

// TestIsolation_JobImagesArePinnedByDigest: a release job's container image
// at a tag can change under the release, also when it comes in through a
// YAML merge key; one that names its registry and is pinned by digest passes.
func TestIsolation_JobImagesArePinnedByDigest(t *testing.T) {
	t.Parallel()

	withImage := func(container string) string {
		return isolationBuild + container + "    steps:\n" + isolationCheckout + isolationSign
	}

	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"a tag", withImage("    container:\n      image: alpine:3\n"), exitValidation},
		{"a tag behind a merge key", "x-base: &base\n  image: alpine:3\n" +
			withImage("    container:\n      <<: *base\n"), exitValidation},
		{"a digest", withImage("    container:\n      image: docker.io/library/alpine:3@sha256:" + strings.Repeat("a", 64) + "\n"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stderr, code := runIsolation(t, writeWorkflowsDir(t, tc.body))
			if code != tc.want {
				t.Fatalf("exit %d, expected %d\nstderr: %s", code, tc.want, stderr)
			}

			if tc.want != 0 {
				assertContains(t, tc.name, stderr, "runs in image alpine:3")
			}
		})
	}
}

// TestIsolation_PrepareCallPassesTheSignersSecrets: prepare-release.yml
// refuses a release before its tag when a secret the release uses is not
// configured, and sees only what its caller passes, so the gate refuses a
// prepare call without a secret the sign job takes. secrets: inherit is no
// way around it: no release job may pass every caller secret.
func TestIsolation_PrepareCallPassesTheSignersSecrets(t *testing.T) {
	t.Parallel()

	workflow := func(prepareSecrets string) string {
		return `jobs:
  prepare:
    uses: examplescope/ci-layer/.forgejo/workflows/prepare-release.yml@` + isolationPin + `
    with:
      forge-ci-sha: ` + isolationPin + `
` + prepareSecrets + `  build-and-release:
    outputs:
      dist-digest: ${{ steps.handoff.outputs.digest }}
    steps: []
  sign-and-publish:
    uses: examplescope/ci-layer/.forgejo/workflows/sign-and-publish-release.yml@` + isolationPin + `
    with:
      forge-ci-sha: ` + isolationPin + `
      release-tag: ${{ needs.prepare.outputs.release-tag }}
      release-sha: ${{ needs.prepare.outputs.release-sha }}
      artifacts-config: ${{ needs.prepare.outputs.artifacts-config }}
      dist-digest: ${{ needs.build-and-release.outputs.dist-digest }}
    secrets:
      GPG_SIGNING_KEY: ${{ secrets.GPG_SIGNING_KEY }}
`
	}

	for _, test := range []struct {
		name, secrets, want string
	}{
		{"passed", "    secrets:\n      GPG_SIGNING_KEY: ${{ secrets.GPG_SIGNING_KEY }}\n", ""},
		{"inherited", "    secrets: inherit\n", "inherits every caller secret (secrets: inherit)"},
		{"left out", "", `prepare job "prepare" call site is missing secret GPG_SIGNING_KEY`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stderr, code := runIsolation(t, writeWorkflowsDir(t, workflow(test.secrets)), "--signing-secret", "GPG_SIGNING_KEY")

			if test.want == "" {
				if code != 0 {
					t.Fatalf("exit %d, expected 0\nstderr: %s", code, stderr)
				}

				return
			}

			if code != exitValidation {
				t.Fatalf("exit %d, expected %d\nstderr: %s", code, exitValidation, stderr)
			}

			assertContains(t, "prepare secrets", stderr, test.want)
		})
	}
}
