// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the `report` verbs — the step-summary and
// stage-result emitters that feed the workflow UI and, crucially, the
// stage gating. They are pure deterministic transforms (flags/JSON in →
// markdown to $GITHUB_STEP_SUMMARY and/or key=value to $GITHUB_OUTPUT),
// so they test on a bare runner with no toolchain.
//
// The load-bearing one is `report stage-result`: it aggregates per-job
// results into a single stage verdict with failure > cancelled > success
// priority and FAIL-CLOSES a planned-but-unrecorded job to failure — the
// gate an orchestrator branches on. The rest render tables whose pass/
// fail wording drives what a human sees.

package blackbox

import (
	"path/filepath"
	"testing"
)

// reportSinks provisions the four env channels a report verb writes to
// and returns their paths plus the env map to hand to run().
type reportSinks struct {
	summary string
	output  string
	results string
	env     map[string]string
}

func newReportSinks(t *testing.T) reportSinks {
	t.Helper()

	d := t.TempDir()
	s := reportSinks{
		summary: filepath.Join(d, "summary.md"),
		output:  filepath.Join(d, "gh-output"),
		results: filepath.Join(d, "ci-results"),
	}
	s.env = map[string]string{
		"GITHUB_ACTIONS":      "true",
		"GITHUB_STEP_SUMMARY": s.summary,
		"GITHUB_OUTPUT":       s.output,
		"CI_RESULTS_DIR":      s.results,
	}

	return s
}

// with returns a copy of the sink env plus the given extra keys.
func (s reportSinks) with(extra map[string]string) map[string]string {
	return mergeEnv(s.env, extra)
}

// TestReportStageResult_Aggregation covers the verdict priority, the
// fail-closed missing-record rule, and the not-run → skipped case.
func TestReportStageResult_Aggregation(t *testing.T) {
	t.Parallel()

	const plan = `{"version":1,"stage":"build","targets":{"maven":{"runs":true},"npm":{"runs":true}}}`

	cases := []struct {
		name       string
		jobResults string
		wantRan    string
		wantResult string
	}{
		{"failure_beats_success", `{"maven":{"result":"success"},"npm":{"result":"failure"}}`, "true", "failure"},
		{"cancelled_beats_success", `{"maven":{"result":"success"},"npm":{"result":"cancelled"}}`, "true", "cancelled"},

		// The top of the documented priority order (failure > cancelled >
		// success), which the two rows above cannot reach: each pits one
		// non-success against success, so an implementation with the priority
		// inverted would satisfy both. A stage that both failed and was
		// cancelled must report failure — an orchestrator that reads
		// "cancelled" may treat it as benign and carry on.
		//
		// Both key orderings are pinned because Go map iteration is randomised:
		// an implementation that took the last-seen result rather than the
		// highest-priority one would be flaky in production, passing most runs.
		{"failure_beats_cancelled", `{"maven":{"result":"failure"},"npm":{"result":"cancelled"}}`, "true", "failure"},
		{"failure_beats_cancelled_reversed", `{"maven":{"result":"cancelled"},"npm":{"result":"failure"}}`, "true", "failure"},
		{"missing_record_fails_closed", `{"maven":{"result":"success"}}`, "true", "failure"},
		{"all_success", `{"maven":{"result":"success"},"npm":{"result":"success"}}`, "true", "success"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newReportSinks(t)

			_, stderr, code := run(t, runOpts{
				dir: t.TempDir(),
				env: s.with(map[string]string{"STAGE_PLAN_JSON": plan, "JOB_RESULTS": tc.jobResults}),
			}, "report", "stage-result", "--extra", "project_type=maven")
			if code != 0 {
				t.Fatalf("stage-result exit %d\nstderr: %s", code, stderr)
			}

			outs := parseGHAOutputs(t, s.output)
			if outs["stage-ran"] != tc.wantRan {
				t.Errorf("stage-ran=%q, want %q", outs["stage-ran"], tc.wantRan)
			}

			if outs["stage-result"] != tc.wantResult {
				t.Errorf("stage-result=%q, want %q", outs["stage-result"], tc.wantResult)
			}

			// The stage manifest carries the same verdict for downstream stages,
			// and the --extra pair lands in it as its own key.
			var manifest struct {
				Result      string `json:"result"`
				ProjectType string `json:"project_type"`
			}
			decodeJSON(t, "manifest", readFile(t, filepath.Join(s.results, "build-result.json")), &manifest)

			if manifest.Result != tc.wantResult || manifest.ProjectType != "maven" {
				t.Errorf("manifest = %+v, want result %q and project_type maven", manifest, tc.wantResult)
			}
		})
	}

	t.Run("not_run_is_skipped", func(t *testing.T) {
		s := newReportSinks(t)

		_, stderr, code := run(t, runOpts{
			dir: t.TempDir(),
			env: s.with(map[string]string{
				"STAGE_PLAN_JSON": `{"version":1,"stage":"build","targets":{"maven":{"runs":false}}}`,
				"JOB_RESULTS":     `{}`,
			}),
		}, "report", "stage-result")
		if code != 0 {
			t.Fatalf("stage-result exit %d\nstderr: %s", code, stderr)
		}

		outs := parseGHAOutputs(t, s.output)
		if outs["stage-ran"] != "false" || outs["stage-result"] != "skipped" {
			t.Errorf("not-run stage: ran=%q result=%q, want false/skipped", outs["stage-ran"], outs["stage-result"])
		}
	})
}

// TestReportStageResult_RejectsBadPlan pins the input contract: a
// missing plan is EX_USAGE (2); a malformed or wrong-version plan is
// EX_CONFIG (78).
func TestReportStageResult_RejectsBadPlan(t *testing.T) {
	t.Parallel()

	// The two 78 rows are different rules reaching the same exit code, so the
	// code alone cannot tell them apart — each pins the sentence naming its own.
	cases := []struct {
		name    string
		plan    *string // nil = don't set STAGE_PLAN_JSON
		want    int
		wantErr string
	}{
		{"missing_plan_is_usage", nil, 2, "stage-plan-json is required"},
		{"malformed_plan_is_config", new(`not json{`), 78, "parse stage plan: not valid JSON"},
		{"wrong_version_is_config", new(`{"version":2,"stage":"build","targets":{}}`), 78, "unsupported version 2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newReportSinks(t)

			extra := map[string]string{}
			if tc.plan != nil {
				extra["STAGE_PLAN_JSON"] = *tc.plan
			}

			_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: s.with(extra)},
				"report", "stage-result")
			if code != tc.want {
				t.Errorf("%s: exit %d, want %d\nstderr: %s", tc.name, code, tc.want, stderr)
			}

			assertContains(t, tc.name, stderr, tc.wantErr)
		})
	}
}

// TestReportPrerequisites_RendersStepSummary renders the release-prerequisites report to the
// step summary. Kept git-free by passing --ref-type branch and no commit.
func TestReportPrerequisites_RendersStepSummary(t *testing.T) {
	t.Parallel()

	t.Run("success_footer_and_publish_rows", func(t *testing.T) {
		s := newReportSinks(t)

		_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "prerequisites",
			"--ref-type", "branch",
			"--project-types", "maven",
			"--publish-to", "maven-central,npmjs",
			"--has-release-token",
			"--has-maven-central-username=false",
			"--sign-artifacts=false",
			"--job-status", "success")
		if code != 0 {
			t.Fatalf("prerequisites exit %d\nstderr: %s", code, stderr)
		}

		body := readFile(t, s.summary)
		for _, want := range []string{
			"Release Prerequisites",
			"branch",
			"RELEASE_TOKEN",
			"All selected prerequisite checks passed",
			"Maven Central",
			"NPM Registry",
		} {
			assertContains(t, "summary", body, want)
		}
	})

	t.Run("failure_job_status_flips_footer", func(t *testing.T) {
		s := newReportSinks(t)

		_, _, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "prerequisites",
			"--ref-type", "branch", "--job-status", "failure")
		if code != 0 {
			t.Fatalf("prerequisites (never fails the pipeline) exit %d", code)
		}

		assertContains(t, "summary", readFile(t, s.summary), "Prerequisites validation failed")
	})

	t.Run("malformed_config_plan_is_config_error", func(t *testing.T) {
		s := newReportSinks(t)

		_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "prerequisites",
			"--ref-type", "branch", "--config-plan-json", "not json{")
		if code != exitConfig {
			t.Errorf("malformed --config-plan-json: exit %d, want 78 (EX_CONFIG)", code)
		}

		assertContains(t, "malformed config plan", stderr, "parse config-plan-json")
	})
}

// TestReportQualityCheck_AggregatesPassFail renders the PR quality-check table from
// positional "name|enabled|result" args and aggregates a pass/fail footer.
func TestReportQualityCheck_AggregatesPassFail(t *testing.T) {
	t.Parallel()

	t.Run("one_enabled_failure_fails_the_summary", func(t *testing.T) {
		s := newReportSinks(t)

		_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "quality-check",
			"nanolinter|true|success", "swiftlint|true|failure",
			"reuse|false|success", "megalint|true|skipped")
		if code != 0 {
			t.Fatalf("quality-check (summary-only, never fails) exit %d\nstderr: %s", code, stderr)
		}

		body := readFile(t, s.summary)
		for _, want := range []string{"nanolinter", "swiftlint", "Some checks failed"} {
			assertContains(t, "summary", body, want)
		}
	})

	t.Run("all_enabled_pass", func(t *testing.T) {
		s := newReportSinks(t)

		_, _, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "quality-check",
			"nanolinter|true|success", "reuse|false|success")
		if code != 0 {
			t.Fatalf("quality-check exit %d", code)
		}

		assertContains(t, "summary", readFile(t, s.summary), "All enabled checks passed")
	})

	// A malformed positional is kept as a row and rendered Unconfirmed, and the
	// footer says so. It used to be dropped, which let a check spec that lost
	// its pipes vanish from the table without a trace; the engine pins the
	// fail-closed shape in TestParseQualityChecks_PreservesMalformedLinesAsUnconfirmed.
	t.Run("malformed_arg_is_kept_as_unconfirmed", func(t *testing.T) {
		s := newReportSinks(t)

		_, _, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "status", "quality-check", "bad", "good|true|success")
		if code != 0 {
			t.Fatalf("quality-check exit %d", code)
		}

		body := readFile(t, s.summary)
		assertContains(t, "summary", body, "| good | ✓ Pass |")
		assertContains(t, "summary", body, "| bad | Unconfirmed |")
		assertContains(t, "summary", body, "Some enabled checks are skipped or unconfirmed")
	})
}

// TestReportSwiftLint_EnabledFailureFailsProcess is the one report verb with an exit-code side
// effect: an ENABLED linter reporting failure fails the process (exit 1),
// after the summary is written; a disabled linter's failure is ignored.
func TestReportSwiftLint_EnabledFailureFailsProcess(t *testing.T) {
	t.Parallel()

	t.Run("enabled_pass_is_zero", func(t *testing.T) {
		s := newReportSinks(t)

		_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "swift-lint", "--enable-swiftlint", "--swiftlint-result", "success")
		if code != 0 {
			t.Fatalf("swift-lint pass exit %d\nstderr: %s", code, stderr)
		}

		assertContains(t, "summary", readFile(t, s.summary), "Swift Linting Summary")
	})

	t.Run("enabled_failure_exits_one_after_writing_summary", func(t *testing.T) {
		s := newReportSinks(t)

		_, _, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "swift-lint", "--enable-swiftlint", "--swiftlint-result", "failure")
		if code != exitValidation {
			t.Errorf("enabled swiftlint failure: exit %d, want 1 (EX_VALIDATION)", code)
		}

		// Summary is appended before the non-zero return.
		assertContains(t, "summary", readFile(t, s.summary), "Linting failed")
	})

	t.Run("disabled_failure_is_ignored", func(t *testing.T) {
		s := newReportSinks(t)

		_, _, code := run(t, runOpts{dir: t.TempDir(), env: s.env},
			"report", "swift-lint", "--swiftlint-result", "failure")
		if code != 0 {
			t.Errorf("disabled swiftlint failure should not fail the process: exit %d", code)
		}
	})
}
