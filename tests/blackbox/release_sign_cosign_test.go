// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Cosign-based artifact signing: local black-box round-trip through the
// `release sign --method=kms --key=<local-cosign-key>` and
// `validate artifact-signature --method=kms --key=<pubkey>` paths.
//
// We don't exercise the Sigstore-keyless path here — it requires a
// live Fulcio + Rekor and an OIDC-emitting runner. The wiring is
// unit-tested in internal/adapters/cosign (argv shape) and
// internal/app/release (dispatch).

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cosignKey generates a local cosign keypair (test.key + test.pub)
// in dir, with an empty passphrase (controlled by COSIGN_PASSWORD=).
// Returns the absolute paths to the private and public keys.
func cosignKey(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	requireTool(t, "cosign")

	cmd := toolCommand(t, dir, map[string]string{"COSIGN_PASSWORD": ""},
		"cosign", "generate-key-pair", "--output-key-prefix", "test")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair: %v\n%s", err, out)
	}

	priv := filepath.Join(dir, "test.key")
	pub := filepath.Join(dir, "test.pub")

	if !fileExists(priv) || !fileExists(pub) {
		t.Fatalf("cosign generate-key-pair did not produce expected files in %s", dir)
	}

	return priv, pub
}

// TestReleaseSign_CosignKMSRoundtrip verifies the full chain:
// `release sign --method=kms --key=<local-key>` produces a .sig
// sidecar, and `validate artifact-signature` accepts it via the
// matching pubkey. A tampered artifact must fail verification.
func TestReleaseSign_CosignKMSRoundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := cosignKey(t, dir)

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign.
	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"COSIGN_PASSWORD": "",
		},
	}, "release", "sign",
		"--method=kms",
		"--key", priv,
		"--release-artifacts-dir", "release-artifacts",
	)
	if code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	bundle := filepath.Join(dir, "app.tgz.bundle")
	if !fileExists(bundle) {
		t.Fatalf("expected %s; not produced", bundle)
	}

	// cosign 3.x emits a single bundle for KMS too — no separate
	// .sig or .pem files.
	if fileExists(filepath.Join(dir, "app.tgz.sig")) || fileExists(filepath.Join(dir, "app.tgz.pem")) {
		t.Errorf("cosign 3.x must emit only .bundle; found stray .sig or .pem")
	}

	// Verify (auto-detected method=kms because --key is supplied).
	// The artifact path is relative to dir; we move it next to its
	// bundle so the validate command finds the sidecar.
	artCopy := filepath.Join(dir, "app.tgz")
	if err := os.Rename(filepath.Join(ra, "app.tgz"), artCopy); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{
		dir: dir,
	}, "validate", "artifact-signature",
		"--artifact", "app.tgz",
		"--key", pub,
	)
	if code != 0 {
		t.Errorf("verify exit %d\nstderr: %s", code, stderr)
	}

	// Tamper: rewrite the artifact and re-verify. Must fail.
	if err := os.WriteFile(artCopy, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: dir}, "validate", "artifact-signature",
		"--artifact", "app.tgz", "--key", pub)
	if code != exitValidation {
		t.Errorf("tampered artifact verify: exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
	}

	assertContains(t, "tampered artifact rejection", stderr, "artifact cosign verification failed")
}

// TestReleaseSign_MethodFlagValidation pins the per-method invariants
// on --key / --oidc-issuer at the CLI boundary. Wrong combos are a
// configuration error (EX_CONFIG, the class the sign.* schema rules
// share) with a specific message; the binary must not even reach the
// cosign subprocess.
func TestReleaseSign_MethodFlagValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cases := []struct {
		name      string
		args      []string
		wantInErr []string
	}{
		{
			name:      "kms-without-key",
			args:      []string{"release", "sign", "--method=kms"},
			wantInErr: []string{"--key is required", "--method=kms"},
		},
		{
			name:      "sigstore-with-key",
			args:      []string{"release", "sign", "--method=sigstore", "--key", "awskms:///alias/X"},
			wantInErr: []string{"--key is forbidden", "--method=sigstore"},
		},
		{
			name:      "kms-with-oidc-issuer",
			args:      []string{"release", "sign", "--method=kms", "--key", "/dev/null", "--oidc-issuer", "https://x"},
			wantInErr: []string{"--oidc-issuer is forbidden", "--method=kms"},
		},
		{
			name:      "gpg-with-key",
			args:      []string{"release", "sign", "--method=gpg", "--key", "./somekey"},
			wantInErr: []string{"--key is forbidden", "--method=gpg"},
		},
		{
			name:      "unknown-method",
			args:      []string{"release", "sign", "--method=openssl"},
			wantInErr: []string{"sign method", "not one of"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := run(t, runOpts{dir: dir}, c.args...)
			if code != exitConfig {
				t.Fatalf("bad flag combo: exit %d, want 78 (EX_CONFIG)\nstderr: %s", code, stderr)
			}

			for _, want := range c.wantInErr {
				assertContains(t, "operator guidance", stderr, want)
			}
		})
	}
}

// TestValidateArtifactSignature_AutoDetectsSidecars pins the sidecar-based
// auto-detection: `.bundle` → cosign (kms or sigstore per flags);
// `.asc` → GPG; both present requires --method explicit.
func TestValidateArtifactSignature_AutoDetectsSidecars(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	art := filepath.Join(dir, "app.tgz")

	if err := os.WriteFile(art, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No sidecars → ErrMissingInput → exit 66 (sysexits EX_NOINPUT).
	_, stderr, code := run(t, runOpts{dir: dir},
		"validate", "artifact-signature", "--artifact", "app.tgz")
	if code != exitNoInput { // EX_NOINPUT
		t.Errorf("no sidecars: expected exit 66, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "missing sidecar", stderr, "no signature sidecar")

	// Dual-sign (.bundle + .asc) → ErrInvalidConfig → exit 78.
	if err := os.WriteFile(art+".bundle", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(art+".asc", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: dir},
		"validate", "artifact-signature", "--artifact", "app.tgz")
	if code != exitConfig { // EX_CONFIG
		t.Errorf("dual-sign: expected exit 78, got %d\nstderr: %s", code, stderr)
	}

	assertContains(t, "dual-sign", stderr, "dual-signed state")
}

// TestValidateArtifactSignature_SidecarPicksTheMethod covers the half of the
// auto-detection contract the test above states but never exercises: it pins
// only the two ERROR cases (no sidecar, both sidecars), so nothing proves
// detection actually picks the right method. A regression that always chose
// cosign would leave it green — and the cosign round-trip would still pass,
// because that is the .bundle path.
//
// The "Verifying <artifact> (method=…, signature=…)" line is the discriminator:
// it names the method that was chosen and the sidecar it was chosen from.
func TestValidateArtifactSignature_SidecarPicksTheMethod(t *testing.T) {
	t.Parallel()

	write := func(t *testing.T, sidecars ...string) (dir string) {
		t.Helper()

		dir = t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "app.tgz"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}

		for _, ext := range sidecars {
			if err := os.WriteFile(filepath.Join(dir, "app.tgz"+ext), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		return dir
	}

	t.Run("asc alone selects gpg", func(t *testing.T) {
		_, stderr, _ := run(t, runOpts{dir: write(t, ".asc")},
			"validate", "artifact-signature", "--artifact", "app.tgz")

		// The run then fails for want of --public-key, which is not what this
		// asserts: the claim is which method the sidecar selected.
		assertContains(t, "asc selects gpg", stderr, "method=gpg")
		assertContains(t, "asc names its sidecar", stderr, "signature=app.tgz.asc")
	})

	// The dual-sign refusal tells the operator to "pass
	// --method=gpg|sigstore|kms explicitly". That instruction is only worth
	// printing if it works, and nothing checked that it does.
	t.Run("explicit method resolves a dual-signed artifact", func(t *testing.T) {
		_, stderr, _ := run(t, runOpts{dir: write(t, ".asc", ".bundle")},
			"validate", "artifact-signature", "--artifact", "app.tgz", "--method", "gpg")

		if strings.Contains(stderr, "dual-signed state") {
			t.Errorf("--method did not resolve the dual-signed state the error told the operator to resolve:\n%s", stderr)
		}

		assertContains(t, "explicit gpg wins", stderr, "method=gpg")
	})

	// .bundle alone is genuinely ambiguous — cosign writes the same file for
	// kms and for keyless — so detection resolves it by which identity
	// constraint the caller supplied. With neither, guessing would verify
	// against the wrong trust model, so it refuses and names both flags.
	// The two bundle tests in this file each supply one constraint (--key in
	// the KMS round-trip, a forge-derived identity in the keyless test), so
	// nothing exercised the refusal.
	t.Run("bundle without an identity constraint refuses", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: write(t, ".bundle")},
			"validate", "artifact-signature", "--artifact", "app.tgz")

		if code != exitNoInput {
			t.Errorf("exit = %d, want 66 (EX_NOINPUT)\nstderr: %s", code, stderr)
		}

		// Both routes out must be named: an operator who is told only one of
		// them cannot tell which trust model they meant to be in.
		assertContains(t, "names the ambiguity", stderr, "no identity constraint supplied")
		assertContains(t, "offers the kms route", stderr, "--key")
		assertContains(t, "offers the sigstore route", stderr, "--cert-identity-regexp")
	})
}
