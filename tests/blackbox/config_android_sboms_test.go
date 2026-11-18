// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Android outputs have no analyzed-artifact SBOM. Defaults select only
// available layers, and an explicit unavailable layer fails at config parsing.
func TestConfigAndroid_SBOMLayers(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		buildType, sboms string
		want             []string
	}{
		"application defaults":          {buildType: "application", want: []string{"build", "analyzed-container"}},
		"library defaults":              {buildType: "library", want: []string{"build"}},
		"unavailable application layer": {buildType: "application", sboms: "build,analyzed-artifact"},
		"unavailable library layer":     {buildType: "library", sboms: "all"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			declaration := "artifacts:\n  - name: app\n    project-type: gradle-android\n    working-directory: .\n    build-type: " + tc.buildType + "\n"
			if tc.sboms != "" {
				declaration += "    sboms: " + tc.sboms + "\n"
			}

			if err := os.MkdirAll(filepath.Join(dir, ".forge-ci"), 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, ".forge-ci", "artifacts.yml"), []byte(declaration), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{"ARTIFACTS_CONFIG": ".forge-ci/artifacts.yml"}},
				"--json", "config", "parse-artifacts")
			if tc.want == nil {
				if code != exitConfig {
					t.Fatalf("exit %d, want %d\nstderr: %s", code, exitConfig, stderr)
				}

				assertContains(t, "refusal", stderr, "there is no analyzed-artifact SBOM for an Android artifact")

				return
			}

			if code != 0 {
				t.Fatalf("exit %d\nstderr: %s", code, stderr)
			}

			var plan struct {
				Artifacts struct {
					All []struct {
						EffectiveSBOMs []string `json:"effective_sboms"`
					} `json:"all"`
				} `json:"artifacts"`
			}

			if err := json.Unmarshal([]byte(unwrapConfigPlan(t, stdout)), &plan); err != nil {
				t.Fatal(err)
			}

			if len(plan.Artifacts.All) != 1 || !slices.Equal(plan.Artifacts.All[0].EffectiveSBOMs, tc.want) {
				t.Fatalf("SBOM layers %+v, want %v", plan.Artifacts.All, tc.want)
			}
		})
	}
}
