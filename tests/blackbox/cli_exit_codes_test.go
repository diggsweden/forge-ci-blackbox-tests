// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExitCodes_Matrix locks down the public exit-code contract of the
// CLI by black-box probing each documented sysexits.h-style class.
// CI policy YAML / orchestrator workflows branch on these values, so
// a regression that flips usage→validation (or vice versa) silently
// breaks the entire stage.
//
//	 1 — EX_VALIDATION  (input present but rejected by a check)
//	 2 — EX_USAGE       (missing flag, unknown subcommand/option)
//	65 — EX_DATAERR     (an input exists but does not parse)
//	66 — EX_NOINPUT     (referenced input file absent)
//	69 — EX_UNAVAILABLE (a required tool or service is missing)
//	77 — EX_NOPERM      (release-authorisation denied)
//	78 — EX_CONFIG      (declared config inconsistent / unsupported)
//
// EX_DATAERR and EX_UNAVAILABLE need an input or a fixture the bare table
// cannot carry, so they are pinned by the two tests below it.
//
// The EX_NOPERM cases are exercised by the validate_signer_allowlist_test.go
// integration test (signer-not-in-allowlist, missing-allowlist-fails-closed);
// they appear there because building the scenario needs a signed tag. Likewise
// EX_NOINPUT is pinned where a real missing input arises (validate
// artifact-signature, release provenance) and EX_CONFIG where a real config is
// rejected (the config_* files); this matrix probes the classes a bare binary
// can reach with no scenario to build.
func TestExitCodes_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		args    []string
		want    int
		wantErr string
	}{
		{
			name:    "invalid_tag_format_is_EX_VALIDATION",
			args:    []string{"validate", "tag", "format", "--tag", "vBOGUS"},
			want:    1,
			wantErr: `invalid tag format: "vBOGUS"`,
		},
		{
			name:    "missing_required_flag_is_EX_USAGE",
			args:    []string{"version", "bump"},
			want:    2,
			wantErr: `Required flags "project-type, version" not set`,
		},
		{
			name:    "unknown_subcommand_is_EX_USAGE",
			args:    []string{"this-subcommand-does-not-exist"},
			want:    2,
			wantErr: `unknown subcommand 'this-subcommand-does-not-exist'`,
		},
		{
			name:    "unknown_project_type_is_EX_USAGE",
			args:    []string{"version", "bump", "--project-type=java", "--version=1.0.0"},
			want:    2,
			wantErr: "unknown project type: java",
		},
		{
			name: "valid_tag_format_is_success",
			args: []string{"validate", "tag", "format", "--tag", "v1.2.3"},
			want: 0,
		},
		// A group invoked without its subcommand must FAIL, not print help and
		// exit 0. This is the omission case: a workflow step that lost its last
		// path segment would otherwise pass green having done nothing, and no
		// surface-level check catches it (the verb path still exists, so
		// forgejo-ci's CLI-invocation contract is satisfied).
		{
			name:    "bare_group_is_EX_USAGE",
			args:    []string{"validate", "tag"},
			want:    2,
			wantErr: `"tag" requires a subcommand`,
		},
		{
			name:    "bare_nested_group_is_EX_USAGE",
			args:    []string{"container", "ledger"},
			want:    2,
			wantErr: `"ledger" requires a subcommand`,
		},
		// The root is no exemption: `forge-ci` alone prints a short start card
		// on stderr and refuses with a usage error, like a bare group. --help
		// and `help` remain the exit-0 requests for the reference (CLI-02).
		{
			name:    "bare_root_is_EX_USAGE_with_a_start_card",
			args:    []string{},
			want:    2,
			wantErr: "START HERE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, code := run(t, runOpts{}, tc.args...)
			if code != tc.want {
				t.Errorf("args=%v want exit %d got %d\nstdout:\n%s\nstderr:\n%s",
					tc.args, tc.want, code, stdout, stderr)
			}

			// Several rows share an exit code; the message says which rule fired.
			if tc.wantErr != "" {
				assertContains(t, tc.name, stderr, tc.wantErr)
			}
		})
	}
}

// TestExitCodes_MalformedInputIsDataErr: an input that exists but does not
// parse is EX_DATAERR (65), distinct from the absent input's 66 and from the
// config class. A workflow that retries on 69 or files a bug on 70 must see
// neither for a corrupt job-results document.
func TestExitCodes_MalformedInputIsDataErr(t *testing.T) {
	t.Parallel()

	s := newReportSinks(t)

	_, stderr, code := run(t, runOpts{
		dir: t.TempDir(),
		env: s.with(map[string]string{
			"STAGE_PLAN_JSON": `{"version":1,"stage":"build","targets":{"maven":{"runs":true}}}`,
			"JOB_RESULTS":     "not json{",
		}),
	}, "report", "stage-result")

	if code != exitDataErr {
		t.Fatalf("malformed JOB_RESULTS: exit %d, want 65 (EX_DATAERR)\nstderr: %s", code, stderr)
	}

	assertContains(t, "names the parse rule", stderr, "parse job-results map")
}

// TestExitCodes_MissingToolIsUnavailable: a tool the command needs but cannot
// find is EX_UNAVAILABLE (69), the class CI reads as "the environment, not the
// input". PATH holds only an empty directory, so no host syft can leak in.
func TestExitCodes_MissingToolIsUnavailable(t *testing.T) {
	t.Parallel()

	proj := copyTree(t, fixture("maven-hello"))

	jar := filepath.Join(proj, "target", "maven-hello-1.0.0.jar")
	if err := os.MkdirAll(filepath.Dir(jar), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(jar, minimalZip(), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{"PATH": t.TempDir()}},
		"sbom", "assemble", "--project-type", "maven", "--layers", "analyzed-artifact",
		"--name", "maven-hello", "--version", "1.0.0")

	if code != exitUnavailable {
		t.Fatalf("syft absent from PATH: exit %d, want 69 (EX_UNAVAILABLE)\nstderr: %s", code, stderr)
	}

	assertContains(t, "names the missing tool", stderr, "syft not found in $PATH")
}
