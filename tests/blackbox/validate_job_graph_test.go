// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `validate job-graph`. A reusable-workflow-call
// job whose if/with reads needs.<P>.outputs, where <P> is skippable (a
// non-always() if), makes the forge abort the whole run with a
// misleading "<P> is missing the output ..." that hides the real
// upstream failure. The validator flags that shape unless the producer
// runs unconditionally or the consumer carries an explicit
// job-graph-guard allow annotation. Pure static YAML analysis.

package blackbox

import "testing"

// TestJobGraph_SkippableProducerFlagged: a consumer reads the outputs of
// a conditionally-skipped producer, so the run can abort with a masked
// error. The validator must reject it.
func TestJobGraph_SkippableProducerFlagged(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `jobs:
  producer:
    if: ${{ github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    outputs:
      images: ${{ steps.c.outputs.images }}
    steps: []
  consumer:
    needs: [producer]
    if: ${{ needs.producer.outputs.images != '[]' }}
    uses: ./.github/workflows/sign.yml
`)

	_, stderr, code := run(t, runOpts{}, "validate", "job-graph", "--workflow", wf)

	if code != exitValidation { // EX_VALIDATION: masking risk
		t.Fatalf("expected EX_VALIDATION=1 for skippable producer, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "job-graph masking", stderr, "is skippable (a non-always() if)")
}

// TestJobGraph_AlwaysProducerClean: an always() producer can't be skipped,
// so reading its outputs is safe.
func TestJobGraph_AlwaysProducerClean(t *testing.T) {
	t.Parallel()

	wf := writeTempWorkflow(t, `jobs:
  producer:
    if: ${{ always() }}
    runs-on: ubuntu-24.04
    outputs:
      images: ${{ steps.c.outputs.images }}
    steps: []
  consumer:
    needs: [producer]
    if: ${{ needs.producer.outputs.images != '[]' }}
    uses: ./.github/workflows/sign.yml
`)

	_, stderr, code := run(t, runOpts{}, "validate", "job-graph", "--workflow", wf)

	if code != 0 {
		t.Fatalf("expected exit 0 for always() producer, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "job-graph clean", stderr, "No reusable-consumer job-graph masking risks")
}

// TestJobGraph_GuardAnnotationSyntax pins how the escape hatch is recognised,
// in both directions.
//
// Suppressing this check is how a workflow run accepts a masked "missing
// output", so the table fixes the accepted syntax:
//
//   - a reason makes it count, in any quoting style and with forgiving
//     whitespace — style is not the point, the record is;
//   - a BARE `allow`, an empty reason and a whitespace-only reason do NOT
//     suppress, and are reported as their own violation. The annotation waives
//     a masking check, so it has to record WHY the edge is provably safe;
//   - the syntax is otherwise strict: a missing colon or different case is not
//     an override at all, so a near-miss fails closed — and gets the GENERIC
//     message, because nothing recognisable was written.
func TestJobGraph_GuardAnnotationSyntax(t *testing.T) {
	t.Parallel()

	// Subtest names feed t.TempDir(), which derives a directory from them.
	// Keep them free of punctuation that the derivation mangles — a comma here
	// produced a truncated path and an EX_NOINPUT that looked like a product
	// failure.
	workflow := func(annotation string) string {
		return `jobs:
  producer:
    if: ${{ github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-24.04
    outputs:
      images: ${{ steps.c.outputs.images }}
    steps: []
  consumer:
    needs: [producer]
` + annotation + `    if: ${{ needs.producer.outputs.images != '[]' }}
    uses: ./.github/workflows/sign.yml
`
	}

	for _, tc := range []struct {
		name       string
		annotation string
		suppresses bool
		wantErr    string // expected refusal text when it does not suppress
	}{
		{"documented form", "    # job-graph-guard: allow reason=\"producer emits an empty list when skipped\"\n", true, ""},

		// Quoting and spacing are not the point; the recorded reason is.
		{"single quoted reason", "    # job-graph-guard: allow reason='provably safe'\n", true, ""},
		{"bare unquoted reason", "    # job-graph-guard: allow reason=provably-safe\n", true, ""},
		{"extra whitespace", "    # job-graph-guard:   allow   reason = \"spaced\"\n", true, ""},

		// An annotation recording nothing waives nothing — and says so, rather
		// than falling back to the generic masking error. An operator who wrote
		// an override and got the generic message would be staring straight at
		// the annotation they thought they had made.
		{"bare allow without a reason", "    # job-graph-guard: allow\n", false, "with no reason"},
		{"empty reason", "    # job-graph-guard: allow reason=\"\"\n", false, "with no reason"},
		{"whitespace only reason", "    # job-graph-guard: allow reason=\"  \"\n", false, "with no reason"},

		// Near misses must NOT override, and must get the GENERIC message:
		// nothing recognisable was written, so pointing at the reason would
		// send the operator to the wrong fix.
		{"missing colon", "    # job-graph-guard allow reason=\"x\"\n", false, "is skippable (a non-always() if)"},
		{"wrong case", "    # JOB-GRAPH-GUARD: allow reason=\"x\"\n", false, "is skippable (a non-always() if)"},
		{"no annotation", "", false, "is skippable (a non-always() if)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wf := writeTempWorkflow(t, workflow(tc.annotation))

			_, stderr, code := run(t, runOpts{}, "validate", "job-graph", "--workflow", wf)

			if tc.suppresses {
				if code != 0 {
					t.Errorf("annotation did not suppress: exit %d\nstderr: %s", code, stderr)
				}

				assertContains(t, tc.name, stderr, "No reusable-consumer job-graph masking risks")

				return
			}

			if code != exitValidation {
				t.Errorf("a non-override was treated as one: exit %d, want 1\nstderr: %s", code, stderr)
			}

			assertContains(t, tc.name, stderr, tc.wantErr)
		})
	}
}
