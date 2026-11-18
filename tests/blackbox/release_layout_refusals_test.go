// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
)

// Assembly mode owns the statement's subjects and output; callers must not
// override either or attach a separate statement signer.
func TestProvenance_AssemblyModeTakesNoOtherSourceOutputOrSigner(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		flags    []string
		wantExit int
		wantErr  string
	}{
		"another checksums file": {[]string{"--checksums-file", "checksums.sha256"}, exitConfig, "--assembly conflicts with --checksums-file"},
		"manifest checksums":     {[]string{"--checksums-from-manifest"}, exitConfig, "--assembly conflicts with --checksums-from-manifest"},
		"another output":         {[]string{"--output", "statement.json"}, exitConfig, "--assembly conflicts with --output"},
		"separate signer":        {[]string{"--method", "kms"}, exitConfig, "--assembly conflicts with --method"},
		"separate key":           {[]string{"--key", "cosign.key"}, exitConfig, "--assembly conflicts with --key"},
		"missing assembly":       {nil, exitNoInput, "release-assembly.json"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir, _ := writeChecksums(t)
			args := append([]string{
				"release", "provenance", "--assembly", ".forge-ci/release-assembly.json",
				"--started-on", provStartedOn, "--go-sum", "",
			}, tc.flags...)
			stdout, stderr, code := run(t, runOpts{dir: dir, env: provenanceEnv}, args...)
			if code != tc.wantExit {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, tc.wantExit, stderr)
			}

			assertContains(t, "refusal", stderr, tc.wantErr)

			if stdout != "" || fileExists(filepath.Join(dir, "statement.json")) {
				t.Errorf("a refused call wrote a statement: stdout %q", stdout)
			}
		})
	}
}

func TestRemovedCommandsAndFlagsAreUsageErrors(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args    []string
		wantErr string
	}{
		"release sbom-zip":                             {[]string{"release", "sbom-zip"}, "sbom-bundle"},
		"sbom assemble --create-zip":                   {[]string{"sbom", "assemble", "--project-type", "maven", "--create-zip"}, "create-zip"},
		"container validate artifacts --containerfile": {[]string{"container", "validate", "artifacts", "--project-type", "maven", "--artifact-dir", ".", "--containerfile", "Containerfile"}, "containerfile"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, stderr, code := run(t, runOpts{dir: t.TempDir()}, tc.args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d (usage)\nstderr: %s", code, exitUsage, stderr)
			}

			assertContains(t, "refusal", stderr, tc.wantErr)
		})
	}
}
