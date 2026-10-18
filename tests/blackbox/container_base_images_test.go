// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `container base-images` is the other half of the workflow-facing
// orchestration boundary (see container_release_images_test.go). forgejo-ci
// drives it from promote-base-container-images.yml and
// verify-base-container-images.yml: it verifies Cosign signatures plus
// CycloneDX and SLSA lineage on a base image before promoting it to an
// immutable tag.
//
// The verify-then-promote happy path needs a real signed and attested image and
// a Cosign keypair, so it is NOT covered here. What is covered is the trust
// root the whole verification hangs from: the pinned public key. If that pin
// can be defeated, every signature check downstream is theatre — so it is worth
// pinning on its own, and it is checkable with no cosign and no registry.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCosignKey writes a stand-in public key into dir and returns its real
// sha256. The bytes never reach cosign: these tests exercise the digest pin
// that gates the key before any verification runs.
func fakeCosignKey(t *testing.T, dir string) (name, sha string) {
	t.Helper()

	name = "cosign.pub"
	path := filepath.Join(dir, name)
	body := "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----\n"

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return name, sha256File(t, path)
}

// runBaseImagesPromote invokes the promote boundary against a key pinned to
// keySHA. Nothing here touches a real registry: the point is where the command
// stops.
func runBaseImagesPromote(t *testing.T, dir, keyPath, keySHA string) (stdout, stderr string, exitCode int) {
	t.Helper()

	return run(t, runOpts{dir: dir, env: map[string]string{"REGISTRY_TOKEN": "test-token"}},
		"container", "base-images", "promote",
		"--server-url", "https://example.org",
		"--repository", "owner/repo",
		"--registry-username", "tester",
		"--expected-workflow", "build.yml",
		"--cosign-public-key-path", keyPath,
		"--cosign-public-key-sha256", keySHA,
		"--all-images-json",
		`[{"name":"demo","candidate_tag":"example.org/owner/repo:staging","final_tag":"example.org/owner/repo:v1"}]`,
	)
}

// TestBaseImagesPromote_RejectsAnUntrustedCosignKey pins the trust root.
//
// The consumer checkout supplies the Cosign public key, and the workflow pins
// its sha256. A key swapped in that checkout — the obvious way to make a
// forged base image verify — must be caught by the pin, because every
// signature and attestation check downstream trusts whatever this key says.
//
// It must also be caught EARLY: the command has to refuse before it
// authenticates anywhere, so a bad trust root never reaches a registry with
// live credentials in hand.
func TestBaseImagesPromote_RejectsAnUntrustedCosignKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath, _ := fakeCosignKey(t, dir)

	const wrongSHA = "0000000000000000000000000000000000000000000000000000000000000000"

	stdout, stderr, code := runBaseImagesPromote(t, dir, keyPath, wrongSHA)
	if code == 0 {
		t.Fatalf("promote accepted a key whose digest does not match the pin\nstdout:%s\nstderr:%s", stdout, stderr)
	}

	assertContains(t, "names the trust root", stderr, "does not match expected trust root")

	// Fail before authenticating: no login may have happened. The string is
	// anchored positively in TestContainerLogin_ForgeTokenFallback, so a
	// wording change there cannot quietly turn this into a vacuous check.
	if strings.Contains(stdout+stderr, "Logged in to") {
		t.Errorf("promote logged in before validating the trust root:\n%s%s", stdout, stderr)
	}
}

// TestBaseImagesPromote_AcceptsThePinnedCosignKey is the negative control for
// the test above: with the pin matching the key on disk, the command moves past
// the trust-root gate and fails later, on the image metadata. Without this, a
// promote that rejected *everything* would still satisfy the rejection test.
func TestBaseImagesPromote_AcceptsThePinnedCosignKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath, keySHA := fakeCosignKey(t, dir)

	stdout, stderr, code := runBaseImagesPromote(t, dir, keyPath, keySHA)
	if code == 0 {
		t.Fatalf("expected the fixture to fail past the key gate, on metadata\nstdout: %s\nstderr: %s", stdout, stderr)
	}

	out := stdout + stderr
	if strings.Contains(out, "does not match expected trust root") {
		t.Fatalf("the correct key digest was rejected by the pin:\n%s", out)
	}

	// It got past the trust root and stopped on the ledger metadata instead.
	assertContains(t, "reached image metadata validation", out, "base image metadata must include")
}
