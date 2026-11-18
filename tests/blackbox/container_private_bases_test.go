// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sign and attest a private loopback image with real Cosign keys and no public
// transparency service. The binary must authenticate all verification reads,
// reject incomplete evidence and reuse the same verified digest twice.
func TestPrivateBaseValidation_RealEvidenceAndAuthenticatedRefusals(t *testing.T) {
	requireTool(t, "cosign")
	fixture := newPrivateInputRegistry(t)
	input := strings.Repeat("a", 64)
	ref := fixture.seed(t, input+"-go", strings.Repeat("b", 40))
	dir := t.TempDir()
	private, public := cosignKey(t, dir)
	auth := fixture.authFile(t, "fixture")
	config := filepath.Dir(auth)
	if err := os.WriteFile(filepath.Join(config, "config.json"), []byte(readFile(t, auth)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flavors"), []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"COSIGN_PASSWORD": "", "DOCKER_CONFIG": config, "REGISTRY_AUTH_FILE": auth}
	invoke := func(args ...string) {
		t.Helper()
		if _, stderr, code := run(t, runOpts{dir: dir, env: env}, args...); code != 0 {
			t.Fatalf("%s: exit=%d %s", args[1], code, stderr)
		}
	}
	args := []string{"container", "base-images", "validate", "--format", "json",
		"--expected-repository", fixture.repo, "--expected-source", "https://source.example/owner/app",
		"--expected-workflow", "base.yml", "--base-input-id", input, "--flavors-file", "flavors",
		"--cosign-public-key-path", filepath.Base(public), "--cosign-public-key-sha256", sha256File(t, public)}
	refuse := func() {
		t.Helper()
		stdout, stderr, code := run(t, runOpts{dir: dir, env: env}, append(args, "--auth-file", auth)...)
		if code != exitValidation || strings.Contains(stdout, "missing_flavors_json") {
			t.Fatalf("incomplete evidence invited reuse/build: exit=%d %s%s", code, stdout, stderr)
		}
	}
	refuse() // No signature.
	invoke("container", "sign", "--method", "kms", "--key", private, ref)
	refuse() // Signature alone is insufficient.
	sbom := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invoke("container", "attest", "--method", "kms", "--key", private, "--type", "cyclonedx", "--predicate", sbom, ref)
	refuse() // Signed SBOM without lineage is insufficient.
	predicate := filepath.Join(dir, "provenance.json")
	body, err := json.Marshal(map[string]any{"buildDefinition": map[string]any{
		"buildType": "https://example.org/build", "externalParameters": map[string]string{
			"source": "git+https://source.example/owner/app", "workflow": "base.yml", "flavor": "go", "base_input_id": input,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(predicate, body, 0o600); err != nil {
		t.Fatal(err)
	}
	invoke("container", "attest", "--method", "kms", "--key", private, "--type", "slsaprovenance1", "--predicate", predicate, ref)
	writes := fixture.writes.Load()
	invalid := fixture.authFile(t, "wrong")
	for _, mode := range []string{"verified", "verified-again", "bad-auth", "missing-auth", "denied", "wrong-lineage"} {
		t.Run(mode, func(t *testing.T) {
			selected := auth
			switch mode {
			case "bad-auth":
				selected = invalid
			case "missing-auth":
				selected = filepath.Join(dir, "missing.json")
			}
			fixture.denied.Store(mode == "denied")
			command := append(append([]string(nil), args...), "--auth-file", selected)
			if mode == "wrong-lineage" {
				for i := range command {
					if command[i] == "base.yml" {
						command[i] = "wrong.yml"
					}
				}
			}
			stdout, stderr, code := run(t, runOpts{dir: dir, env: env}, command...)
			if strings.HasPrefix(mode, "verified") {
				var result struct {
					Found   bool   `json:"all_found"`
					Missing string `json:"missing_flavors_json"`
					Images  string `json:"all_images_json"`
				}
				if code != 0 || json.Unmarshal([]byte(stdout), &result) != nil || !result.Found || result.Missing != "[]" || !strings.Contains(result.Images, ref) {
					t.Fatalf("verified reuse: exit=%d %s%s", code, stdout, stderr)
				}

				return
			}

			want := exitNoPerm
			switch mode {
			// A missing auth file is the operation's failure, never the
			// "image absent" answer (66) that would invite a build.
			case "missing-auth", "wrong-lineage":
				want = exitValidation
			}

			if code != want || strings.Contains(stdout, "missing_flavors_json") {
				t.Fatalf("authenticated refusal invited build: exit=%d want=%d %s%s", code, want, stdout, stderr)
			}

			// It shares exit 1 with a wrong lineage, so the message tells
			// them apart.
			if mode == "missing-auth" {
				assertContains(t, "names the auth file", stderr, "open registry auth file")
			}
		})
	}
	if fixture.writes.Load() != writes {
		t.Fatal("base verification mutated the registry")
	}
}
