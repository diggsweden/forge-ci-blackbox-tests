// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

package scripts_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Invalid byte limits must be refused before evidence is removed or sealed.
func TestEvidenceLimitsRefuseInvalidInputBeforeMutation(t *testing.T) {
	t.Parallel()

	for _, script := range []string{"bound-evidence-bundle.sh", "seal-evidence-bundle.sh"} {
		for _, limit := range []string{"text", "1+1", "-1", "0", "01", "9223372036854775808"} {
			t.Run(script+"/"+limit, func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()
				files := []string{"payload.txt", "metadata.txt", "evidence-truncations.txt"}
				for _, name := range files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("keep"), 0o600); err != nil {
						t.Fatal(err)
					}
				}

				cmd := exec.CommandContext(t.Context(), "bash", filepath.Join("..", "scripts", script), dir, limit)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LC_ALL=C"}
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 {
					t.Fatalf("invalid limit: err=%v, want usage exit 2: %s", err, output)
				}

				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != len(files) {
					t.Fatalf("evidence file set changed: %v, %v", entries, err)
				}
				for _, name := range files {
					path := filepath.Join(dir, name)
					body, err := os.ReadFile(path)
					if err != nil || string(body) != "keep" {
						t.Errorf("%s changed: %q, %v", name, body, err)
					}
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0o600 {
						t.Errorf("%s permissions changed: %v", name, err)
					}
				}
			})
		}
	}
}

func TestEvidenceLimitsAcceptDecimalBounds(t *testing.T) {
	t.Parallel()

	for _, script := range []string{"bound-evidence-bundle.sh", "seal-evidence-bundle.sh"} {
		for _, limit := range []string{"15728640", "9223372036854775807"} {
			t.Run(script+"/"+limit, func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()
				payload := filepath.Join(dir, "payload.txt")
				if err := os.WriteFile(payload, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}

				cmd := exec.CommandContext(t.Context(), "bash", filepath.Join("..", "scripts", script), dir, limit)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LC_ALL=C"}
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("valid limit: %v: %s", err, output)
				}

				if body, err := os.ReadFile(payload); err != nil || string(body) != "keep" {
					t.Fatalf("payload changed: %q, %v", body, err)
				}
			})
		}
	}
}
