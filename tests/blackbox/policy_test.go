// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestPolicyShowExplicitEnforcement(t *testing.T) {
	t.Parallel()

	for _, enabled := range []string{"true", "false"} {
		t.Run(enabled, func(t *testing.T) {
			stdout, stderr, code := run(t, runOpts{}, "--enforce-application-tests="+enabled, "policy", "show")
			if code != 0 {
				t.Fatalf("policy show: %d: %s", code, stderr)
			}
			var policy struct {
				Settings map[string]bool   `json:"settings"`
				Sources  map[string]string `json:"sources"`
				Digest   string            `json:"default-sha256"`
			}
			if err := json.Unmarshal([]byte(stdout), &policy); err != nil {
				t.Fatal(err)
			}
			value, exists := policy.Settings["enforce-application-tests"]
			if !exists || value != (enabled == "true") || policy.Sources["enforce-application-tests"] != "flag" {
				t.Fatalf("explicit policy was not reported: %s", stdout)
			}
			if digest, err := hex.DecodeString(policy.Digest); err != nil || len(digest) != 32 {
				t.Fatalf("invalid embedded-policy digest: %q", policy.Digest)
			}
		})
	}
}

func TestPolicyReportOnlyStillRejectsSkippingTests(t *testing.T) {
	t.Parallel()

	_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "--enforce-application-tests=false", "build", "npm", "run", "--skip-tests")
	if code != exitUsage {
		t.Fatalf("skip-tests: exit %d, want %d: %s", code, exitUsage, stderr)
	}
	assertContains(t, "mandatory test execution", stderr, "skip-tests cannot disable")
}
