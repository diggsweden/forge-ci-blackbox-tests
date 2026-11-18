// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `plan release` and `plan release-file-signing` decide, before any job runs,
// which runners a release needs and how its files are signed.
package blackbox

import (
	"encoding/json"
	"testing"
)

const planGoArtifact = `
artifacts:
  - name: app
    project-type: go
    config:
      build-mode: artifact-first
`

// TestPlanRelease_RunnerInputsAreRequiredOnAForge: on a forge a release is
// never planned unchecked. Without any --runner-input the plan is refused as a
// usage error; with the layer's inputs it composes. A --provider local run has
// no runners and passes none.
func TestPlanRelease_RunnerInputsAreRequiredOnAForge(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, planGoArtifact)
	env := map[string]string{"CONFIG_PLAN_JSON": configPlanJSON(t, repo)}
	release := []string{"plan", "release", "--tag", "v1.2.3", "--branch", "main", "--repository-visibility", "public"}
	onGitHub := append([]string{"--provider", "github", "--runner", "github", "--json"}, release...)

	_, stderr, code := run(t, runOpts{dir: repo, env: env}, onGitHub...)
	if code != exitUsage {
		t.Fatalf("plan release without runner inputs: exit %d, want %d: %s", code, exitUsage, stderr)
	}

	assertContains(t, "names the flag", stderr, "pass --runner-input")

	onGitHub = append(onGitHub, "--runner-input", `build-runs-on-linux-amd64=["ubuntu-latest"]`)
	if _, stderr, code = run(t, runOpts{dir: repo, env: env}, onGitHub...); code != 0 {
		t.Fatalf("plan release with a runner input: exit %d: %s", code, stderr)
	}

	local := append([]string{"--provider", "local", "--runner", "local", "--json"}, release...)
	if _, stderr, code = run(t, runOpts{dir: repo, env: env}, local...); code != 0 {
		t.Fatalf("local plan release: exit %d: %s", code, stderr)
	}
}

// TestPlanRelease_AndroidApplicationCarriesItsAPK: a release of an Android
// application downloads the release APK beside the AAB, so the application
// can be installed from the release itself.
func TestPlanRelease_AndroidApplicationCarriesItsAPK(t *testing.T) {
	t.Parallel()

	repo := writeArtifactsRepo(t, `
artifacts:
  - name: app
    project-type: gradle-android
    build-type: application
    sboms: none
    config:
      java-version: 21
      build-module: app
      build-types: release
`)
	env := map[string]string{"CONFIG_PLAN_JSON": configPlanJSON(t, repo)}

	stdout, stderr, code := run(t, runOpts{dir: repo, env: env}, "--provider", "local", "--runner", "local", "--json",
		"plan", "release", "--tag", "v1.2.3", "--branch", "main", "--repository-visibility", "public")
	if code != 0 {
		t.Fatalf("plan release: exit %d: %s", code, stderr)
	}

	var out struct {
		Transfers string `json:"artifact-transfer-plan-json"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}

	var transfers struct {
		Items []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out.Transfers), &transfers); err != nil {
		t.Fatalf("transfer plan is not JSON: %v\n%s", err, out.Transfers)
	}

	got := map[string]bool{}
	for _, item := range transfers.Items {
		got[item.Kind+" "+item.Name] = true
	}

	for _, want := range []string{"build_artifact app", "build_artifact app-release"} {
		if !got[want] {
			t.Errorf("transfer plan lacks %q: %s", want, out.Transfers)
		}
	}
}

// TestPlanReleaseFileSigning_FollowsTheDeclaration: checksums and SBOMs are
// signed with GPG only when the declaration says so, and with the Cosign key
// otherwise, also when there is no declaration at all.
func TestPlanReleaseFileSigning_FollowsTheDeclaration(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		artifacts string
		want      string
	}{
		"no_declaration": {want: "cosign"},
		"no_sign_block":  {artifacts: planGoArtifact, want: "cosign"},
		"method_gpg":     {artifacts: planGoArtifact + "sign:\n  method: gpg\n", want: "gpg"},
		"files_method_gpg": {
			artifacts: planGoArtifact + "sign:\n  method: kms\n  key: hashivault://transit/keys/release\n  files-method: gpg\n",
			want:      "gpg",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := t.TempDir()
			if test.artifacts != "" {
				repo = writeArtifactsRepo(t, test.artifacts)
			}

			stdout, stderr, code := run(t, runOpts{dir: repo}, "--json", "plan", "release-file-signing")
			if code != 0 {
				t.Fatalf("plan release-file-signing: exit %d: %s", code, stderr)
			}

			var plan struct {
				Signing string `json:"release-file-signing"`
			}
			if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
				t.Fatalf("output is not JSON: %v\n%s", err, stdout)
			}

			if plan.Signing != test.want {
				t.Fatalf("release-file-signing = %q, want %q", plan.Signing, test.want)
			}
		})
	}
}

// TestPlanReleaseFileSigning_RefusesWhatItCannotRead: a named file that is
// absent is a missing input, and files-method beside a method that already
// signs files with GPG is a configuration error. Neither may fall back to
// "cosign", which would sign the files with the wrong key.
func TestPlanReleaseFileSigning_RefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "plan", "release-file-signing", "--file", "absent.yml")
	if code != exitNoInput {
		t.Fatalf("absent --file: exit %d, want %d: %s", code, exitNoInput, stderr)
	}

	repo := writeArtifactsRepo(t, planGoArtifact+"sign:\n  method: gpg\n  files-method: gpg\n")

	_, stderr, code = run(t, runOpts{dir: repo}, "plan", "release-file-signing")
	if code != exitConfig {
		t.Fatalf("files-method beside method gpg: exit %d, want %d: %s", code, exitConfig, stderr)
	}

	assertContains(t, "names the setting", stderr, "sign.files-method")
}
