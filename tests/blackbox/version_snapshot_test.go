// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestGenerateSnapshot_ComposesFromTagBranchSHA covers `version generate-snapshot`, the
// command behind the branch-triggered snapshot flow. It composes a
// content-addressed version string of the shape
// `<base>-snapshot-<sanitised-branch>-<short-sha>`, where the base is the
// latest `vMAJOR.MINOR.PATCH` tag (falling back to 0.0.0 when the repo has
// no release tag yet), the branch is path-sanitised (`/` → `-`), and the
// SHA is the 7-char HEAD prefix.
// This is the snapshot counterpart to the production version-bump coverage in
// version_bump_matrix_test.go and pins the current naming contract end to end.
func TestGenerateSnapshot_ComposesFromTagBranchSHA(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")

	shortSHA := regexp.MustCompile(`^[0-9a-f]{7}$`)

	t.Run("no_tag_defaults_to_0.0.0_base", func(t *testing.T) {
		repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
			seedCommit(t, repo, runGit)
		})

		outFile := filepath.Join(t.TempDir(), "ghout")
		stdout, stderr, code := run(t, runOpts{
			dir: repo,
			// GITHUB_ACTIONS selects the $GITHUB_OUTPUT sink (local mode
			// discards CI outputs) and the github output format that mirrors
			// snapshot-version into the sink.
			env: map[string]string{"GITHUB_OUTPUT": outFile, "GITHUB_ACTIONS": "true"},
		}, "version", "generate-snapshot", "--ref-name", "feature/awesome-thing")
		if code != 0 {
			t.Fatalf("generate-snapshot exit=%d stderr=%s", code, stderr)
		}

		got := strings.TrimSpace(stdout)

		const wantPrefix = "0.0.0-snapshot-feature-awesome-thing-"
		if !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("version = %q, want prefix %q", got, wantPrefix)
		}

		if sha := strings.TrimPrefix(got, wantPrefix); !shortSHA.MatchString(sha) {
			t.Errorf("short-sha suffix = %q, want 7 lowercase hex chars (full=%q)", sha, got)
		}

		// The same value is mirrored to $GITHUB_OUTPUT as snapshot-version
		// for downstream workflow steps.
		if outs := parseGHAOutputs(t, outFile); outs["snapshot-version"] != got {
			t.Errorf("snapshot-version output = %q, want %q (stdout)", outs["snapshot-version"], got)
		}
	})

	t.Run("base_comes_from_latest_semver_tag", func(t *testing.T) {
		repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
			seedCommit(t, repo, runGit)
			// Out-of-order on purpose: the command must select the highest
			// semver, not the most recently created tag.
			//
			// v1.9.0 / v1.10.0 is the pair that makes this test discriminating.
			// The previous fixture (v1.0.0, v1.4.2, v1.3.0) had the highest
			// semver ALSO be the lexically highest, so a plain string sort
			// produced the same answer and the test could not tell semver
			// ordering from string ordering. Lexically "v1.9.0" > "v1.10.0";
			// by semver 1.10.0 wins.
			for _, tag := range []string{"v1.0.0", "v1.10.0", "v1.9.0", "v1.3.0"} {
				if err := runGit("tag", tag); err != nil {
					t.Fatalf("git tag %s: %v", tag, err)
				}
			}
		})

		stdout, stderr, code := run(t, runOpts{dir: repo},
			"version", "generate-snapshot", "--ref-name", "main")
		if code != 0 {
			t.Fatalf("generate-snapshot exit=%d stderr=%s", code, stderr)
		}

		const wantPrefix = "1.10.0-snapshot-main-"
		if got := strings.TrimSpace(stdout); !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("version = %q, want prefix %q — a lexical sort would pick v1.9.0", got, wantPrefix)
		}
	})

	// The base is documented as the latest `vMAJOR.MINOR.PATCH` tag. Two kinds
	// of tag must therefore be skipped, and neither was exercised: a
	// pre-release (v2.0.0-rc1 is higher by any ordering, but it is not a
	// stable release) and a tag that is not a version at all. Selecting either
	// would put a snapshot on a base that was never released.
	t.Run("prerelease_and_non_version_tags_are_ignored", func(t *testing.T) {
		repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
			seedCommit(t, repo, runGit)

			for _, tag := range []string{"v1.4.2", "v2.0.0-rc1", "not-a-version", "release-request/v3.0.0"} {
				if err := runGit("tag", tag); err != nil {
					t.Fatalf("git tag %s: %v", tag, err)
				}
			}
		})

		stdout, stderr, code := run(t, runOpts{dir: repo},
			"version", "generate-snapshot", "--ref-name", "main")
		if code != 0 {
			t.Fatalf("generate-snapshot exit=%d stderr=%s", code, stderr)
		}

		const wantPrefix = "1.4.2-snapshot-main-"
		if got := strings.TrimSpace(stdout); !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("version = %q, want prefix %q — a pre-release or non-version tag was selected as the base", got, wantPrefix)
		}
	})
}

// TestPlanSnapshotRelease_EmitsStageContracts covers `plan snapshot-release`, the planner that
// turns a parsed config plan into the snapshot flow's three stage contracts
// (release / build / publish). It mirrors how the orchestrator's
// setup-snapshot job wires `config parse-artifacts` → `plan snapshot-release`.
//
// It also pins a post-refactor invariant: the snapshot flow builds NO
// containers, so the emitted plan must carry none of the removed container
// residue (top-level has_containers, the publish_container policy flag, or a
// publish-stage `containers` target). The cargo/go container-FIRST SBOM
// targets are a different concern and legitimately remain.
func TestPlanSnapshotRelease_EmitsStageContracts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	artifacts := filepath.Join(dir, "artifacts.yml")
	if err := os.WriteFile(artifacts,
		[]byte("artifacts:\n  - name: web\n    project-type: npm\n    working-directory: .\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	// Step 1: parse artifacts.yml into the typed config-plan the planner
	// consumes (pure Go — no toolchain needed).
	cfgOut := filepath.Join(dir, "cfgout")

	_, stderr, code := run(t, runOpts{
		dir: dir,
		// GITHUB_ACTIONS selects the $GITHUB_OUTPUT sink; local runner mode
		// discards CI outputs.
		env: map[string]string{"ARTIFACTS_CONFIG": artifacts, "GITHUB_OUTPUT": cfgOut, "GITHUB_ACTIONS": "true"},
	}, "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("config parse-artifacts exit=%d stderr=%s", code, stderr)
	}

	configPlan := parseGHAOutputs(t, cfgOut)["config-plan-json"]
	if configPlan == "" {
		t.Fatal("config parse-artifacts emitted no config-plan-json")
	}

	// Step 2: compose the snapshot-release plan from it.
	planOut := filepath.Join(dir, "planout")

	_, stderr, code = run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"CONFIG_PLAN_JSON": configPlan,
			"PROJECT_TYPE":     "npm",
			"BRANCH":           "feature/snap",
			"RELEASE_SHA":      "abcdef0",
			"PUBLISH_NPM":      "true",
			"USE_CI_TOKEN":     "true",
			"GITHUB_OUTPUT":    planOut,
			"GITHUB_ACTIONS":   "true",
		},
	}, "plan", "snapshot-release")
	if code != 0 {
		t.Fatalf("plan snapshot-release exit=%d stderr=%s", code, stderr)
	}

	outs := parseGHAOutputs(t, planOut)

	// All three stage contracts are emitted.
	for _, key := range []string{
		"snapshot-release-plan-json",
		"snapshot-build-stage-plan-json",
		"snapshot-publish-stage-plan-json",
	} {
		if outs[key] == "" {
			t.Errorf("missing output %q", key)
		}
	}

	var plan struct {
		Version int `json:"version"`
		Context struct {
			Branch string `json:"branch"`
		} `json:"context"`
		Policy struct {
			PublishNPM bool `json:"publish_npm"`
		} `json:"policy"`
	}
	decodeJSON(t, "snapshot plan", outs["snapshot-release-plan-json"], &plan)

	if plan.Version != 1 || plan.Context.Branch != "feature/snap" || !plan.Policy.PublishNPM {
		t.Errorf("snapshot plan = %+v, want version 1, branch feature/snap, publish_npm", plan)
	}

	var build struct {
		Stage string `json:"stage"`
	}
	decodeJSON(t, "snapshot build stage", outs["snapshot-build-stage-plan-json"], &build)

	var publish struct {
		Stage   string `json:"stage"`
		Targets struct {
			NPM struct {
				Runs bool `json:"runs"`
			} `json:"npm"`
		} `json:"targets"`
	}
	decodeJSON(t, "snapshot publish stage", outs["snapshot-publish-stage-plan-json"], &publish)

	// dev-build / dev-publish are the stable internal stage identifiers the
	// renamed snapshot flow still emits — the rename touched the
	// orchestrator/CLI surface, not these JSON stage strings.
	if build.Stage != "dev-build" || publish.Stage != "dev-publish" {
		t.Errorf("stages = %q, %q, want dev-build, dev-publish", build.Stage, publish.Stage)
	}

	// npm is a runnable publish target for an npm project with publish-npm on.
	if !publish.Targets.NPM.Runs {
		t.Error("snapshot publish stage: npm target does not run")
	}

	// The scanner must find a nested key that is present, or the misses below
	// prove nothing.
	if !jsonHasKey(t, outs["snapshot-publish-stage-plan-json"], "npm") {
		t.Fatal("jsonHasKey missed the nested npm target; the residue checks would pass vacuously")
	}

	// Regression: none of the removed container residue may reappear, at any
	// depth of either document.
	for _, doc := range []string{outs["snapshot-release-plan-json"], outs["snapshot-publish-stage-plan-json"]} {
		for _, banned := range []string{"has_containers", "publish_container", "containers"} {
			if jsonHasKey(t, doc, banned) {
				t.Errorf("snapshot plan must not contain removed container residue %q", banned)
			}
		}
	}
}

// decodeJSON unmarshals doc into v, failing the test with the document.
func decodeJSON(t *testing.T, label, doc string, v any) {
	t.Helper()

	if err := json.Unmarshal([]byte(doc), v); err != nil {
		t.Fatalf("%s: decode: %v\n%s", label, err, doc)
	}
}

// jsonHasKey reports whether key names an object member anywhere in doc.
func jsonHasKey(t *testing.T, doc, key string) bool {
	t.Helper()

	var root any
	decodeJSON(t, "json key scan", doc, &root)

	var walk func(v any) bool
	walk = func(v any) bool {
		switch node := v.(type) {
		case map[string]any:
			if _, ok := node[key]; ok {
				return true
			}

			for _, child := range node {
				if walk(child) {
					return true
				}
			}
		case []any:
			return slices.ContainsFunc(node, walk)
		}

		return false
	}

	return walk(root)
}

// seedCommit writes a file and records one unsigned commit so HEAD exists
// for the version commands' `git rev-parse`.
func seedCommit(t *testing.T, repo string, runGit func(args ...string) error) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"add", "-A"},
		{"commit", "-q", "-m", "init", "--no-gpg-sign"},
	} {
		if err := runGit(args...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
}

// parseGHAOutputs reads a $GITHUB_OUTPUT file written by the CLI's output
// sink and returns its key→value pairs. It handles both encodings the sink
// emits: scalar `key=value` lines and the multiline heredoc form
// `key<<EOF_<hex>` … `EOF_<hex>`.
func parseGHAOutputs(t *testing.T, path string) map[string]string {
	t.Helper()

	out := map[string]string{}
	lines := strings.Split(readFile(t, path), "\n")

	for i := 0; i < len(lines); i++ {
		if m := ghaHeredocRE.FindStringSubmatch(lines[i]); m != nil {
			key, delim := m[1], m[2]

			var buf []string
			for i++; i < len(lines) && lines[i] != delim; i++ {
				buf = append(buf, lines[i])
			}

			if i == len(lines) {
				t.Fatalf("%s: heredoc %s for %q is never terminated", path, delim, key)
			}

			out[key] = strings.Join(buf, "\n")

			continue
		}

		if m := ghaScalarRE.FindStringSubmatch(lines[i]); m != nil {
			out[m[1]] = m[2]
		}
	}

	return out
}

//nolint:gochecknoglobals // read-only compiled patterns for the $GITHUB_OUTPUT parser.
var (
	ghaHeredocRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)<<(EOF_[0-9a-f]+)$`)
	ghaScalarRE  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)=(.*)$`)
)
