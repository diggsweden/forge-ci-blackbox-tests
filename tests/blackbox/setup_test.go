// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `forge-ci setup status` lists the steps to a first release. It reads the
// same checks as doctor, so the two must agree about what is done.
package blackbox

import "testing"

// TestSetupStatus_FollowsTheRepository: the workflow step and the doctor step
// are open in a repository without a workflow and done in one with it, as
// doctor itself answers in doctor_test.go. Listing is not a gate, so both runs
// exit 0. Steps the repository cannot show, such as the forge's secrets, stay
// marked [?].
func TestSetupStatus_FollowsTheRepository(t *testing.T) {
	t.Parallel()

	const artifacts = `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
`
	env := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "fixture/integration"}

	stdout, stderr, code := run(t, runOpts{dir: writeArtifactsRepo(t, artifacts), env: env}, "setup", "status", "--root", ".")
	if code != 0 {
		t.Fatalf("setup status: exit %d: %s", code, stderr)
	}

	assertContains(t, "open workflow step", stdout, "[ ] 1. Write the Forge CI files")
	assertContains(t, "doctor fails here", stdout, "[ ] 5. Pass forge-ci doctor")
	assertContains(t, "step it cannot see", stdout, "[?] 4. Create the release secrets")

	stdout, stderr, code = run(t, runOpts{dir: writeDoctorRepo(t, artifacts), env: env}, "setup", "status", "--root", ".")
	if code != 0 {
		t.Fatalf("setup status with a workflow: exit %d: %s", code, stderr)
	}

	assertContains(t, "finished workflow step", stdout, "[x] 1. Write the Forge CI files")
	assertContains(t, "doctor passes here", stdout, "[x] 5. Pass forge-ci doctor")
}
