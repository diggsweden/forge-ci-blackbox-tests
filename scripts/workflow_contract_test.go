// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

package scripts_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the actual script's workflow selection before its compile step.
// The compiler is an inert sentinel; no suite, engine or network operation runs.
func TestCompatibilityContractUsesActiveWorkflowAndNeutralDefaults(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("the contract script requires GNU stat and du")
	}

	body, err := os.ReadFile("validate-strict-profile-contract.sh")
	if err != nil {
		t.Fatal(err)
	}

	const valid = "DEFAULT_REPOSITORY: ${{ vars.FORGE_CI_REPOSITORY || 'fixture/renamed-engine' }}\n" +
		"DEFAULT_REF: ${{ vars.FORGE_CI_REF || 'trunk' }}\n" +
		"name: ${{ inputs['forge-ci-ref'] || vars.FORGE_CI_REF || 'trunk' }}\n"

	for _, scenario := range []struct {
		name, github, forgejo string
		forgejoDir            bool
		want                  int
	}{
		{"GitHub fork", valid, "", false, 42},
		{"Forgejo overrides inert GitHub", "invalid", valid, true, 42},
		{"missing active Forgejo file", valid, "", true, 1},
		{"missing overrides", "name: broken\n", "", false, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			write := func(relative string, content []byte, mode os.FileMode) {
				t.Helper()
				file := filepath.Join(root, relative)
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, content, mode); err != nil {
					t.Fatal(err)
				}
			}

			write("scripts/contract.sh", body, 0o600)
			write("bin/go", []byte("#!/bin/sh\nexit 42\n"), 0o700)
			write(".github/workflows/integration.yml", []byte(scenario.github), 0o600)
			if scenario.forgejoDir {
				if err := os.MkdirAll(filepath.Join(root, ".forgejo/workflows"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.forgejo != "" {
				write(".forgejo/workflows/integration.yml", []byte(scenario.forgejo), 0o600)
			}

			command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts/contract.sh")) //nolint:gosec // copied repository script, test-owned paths and inert compiler.
			command.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+root)
			output, runErr := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(runErr, &exit) || exit.ExitCode() != scenario.want {
				t.Fatalf("err=%v, want exit %d: %s", runErr, scenario.want, output)
			}
			if scenario.want == 42 && !strings.Contains(string(output), "supports repository/ref overrides") {
				t.Fatalf("did not reach the compiler sentinel after validating overrides: %s", output)
			}
		})
	}
}
