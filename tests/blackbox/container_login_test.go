// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// `container login` registry-auth federation: when no password is
// supplied, it falls back to the forge's runner-injected credentials,
// but only for that forge's own registry. Lets a job push to its
// registry without a separately managed secret.
package blackbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestContainerLogin_ForgeTokenFallback verifies that with no password,
// login to the forge's own registry (ghcr.io on GitHub) writes the
// runner token ($GITHUB_TOKEN) as the credential.
func TestContainerLogin_ForgeTokenFallback(t *testing.T) {
	t.Parallel()

	authFile := filepath.Join(t.TempDir(), "config.json")

	_, stderr, code := run(t, runOpts{env: map[string]string{
		"GITHUB_ACTIONS": "true",
		// A real GitHub runner always sets the server URL; the ghcr
		// resolver requires it to refuse GHE hosts.
		"GITHUB_SERVER_URL":  "https://github.com",
		"GITHUB_TOKEN":       "ghs_runnertoken",
		"GITHUB_ACTOR":       "ci-bot",
		"REGISTRY_AUTH_FILE": authFile,
	}}, "container", "login", "--registry", "ghcr.io")
	if code != 0 {
		t.Fatalf("container login (forge fallback) exit %d\nstderr: %s", code, stderr)
	}

	values, err := dockerConfigCredentialValues([]byte(readFile(t, authFile)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(values, dockerCredentialValue{registry: "ghcr.io", field: "auth", value: "ci-bot:ghs_runnertoken"}) {
		t.Errorf("decoded Docker config does not contain the expected ghcr.io auth credential: %#v", values)
	}

	// Positive anchor for the "Logged in to" success line. The ordering
	// check in TestBaseImagesPromote_RejectsAnUntrustedCosignKey asserts the
	// ABSENCE of this string; that negative only proves anything while a
	// successful login demonstrably emits it. If this assertion fails after
	// an engine wording change, update both places together.
	assertContains(t, "login success line", stderr, "Logged in to")
}

// TestContainerLogin_NoFallbackForForeignRegistry verifies the runner
// token is NOT sent to an unrelated registry: with no password and a
// non-forge registry, login fails rather than leaking the token.
func TestContainerLogin_NoFallbackForForeignRegistry(t *testing.T) {
	t.Parallel()

	authFile := filepath.Join(t.TempDir(), "config.json")

	const runnerToken = "ghs_runnertoken"

	stdout, stderr, code := run(t, runOpts{env: map[string]string{
		"GITHUB_ACTIONS": "true",
		// A real GitHub runner always sets the server URL; the ghcr
		// resolver requires it to refuse GHE hosts.
		"GITHUB_SERVER_URL":  "https://github.com",
		"GITHUB_TOKEN":       runnerToken,
		"GITHUB_ACTOR":       "ci-bot",
		"REGISTRY_AUTH_FILE": authFile,
	}}, "container", "login", "--registry", "docker.io")
	if code == 0 {
		t.Fatalf("login to a foreign registry with no password should fail (no token leak); got exit 0")
	}

	// The refusal must name the missing credential rather than failing for an
	// unrelated reason, or "exit non-zero" is the whole assertion.
	assertContains(t, "names the missing password", stderr, "the registry password is required")

	// This refusal normally writes no auth file. If an implementation starts
	// writing one, it still must not contain the ambient runner token.
	if fileExists(authFile) {
		assertDockerConfigDoesNotContainCredentials(t, authFile, runnerToken)
	}

	// The half nothing covered: a token the command refuses to send to the
	// registry must not reach the log either.
	if strings.Contains(stdout+stderr, runnerToken) {
		t.Errorf("the runner token was echoed to the command output:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

func TestDockerConfigCredentialValues_DecodesAndInspectsTokenFields(t *testing.T) {
	t.Parallel()

	values, err := dockerConfigCredentialValues([]byte(`{
  "auths": {
    "registry.example": {
      "auth": "dXNlcjphdXRoLXNlY3JldA==",
      "identitytoken": "identity-secret",
      "registrytoken": "registry-secret",
      "username": "user",
      "password": "password-secret"
    }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"auth":          "user:auth-secret",
		"identitytoken": "identity-secret",
		"password":      "password-secret",
		"registrytoken": "registry-secret",
		"username":      "user",
	}
	for _, value := range values {
		if value.registry != "registry.example" {
			t.Errorf("registry = %q, want registry.example", value.registry)
		}
		if want[value.field] != value.value {
			t.Errorf("credential %s = %q, want %q", value.field, value.value, want[value.field])
		}
		delete(want, value.field)
	}
	for field := range want {
		t.Errorf("credential field %s was not inspected", field)
	}
}
