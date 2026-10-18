// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// SEC: the signer's pre-flight trust anchor check. Before a job signs
// anything, `validate signing-key` derives the public half of the key it was
// handed and refuses unless that half is the public key the project publishes.
//
// A cosign stand-in on PATH plays the private key: whichever public key it
// prints is the key the job "holds". That makes the two outcomes separable
// without a real keypair, and lets the isolation case observe what the cosign
// subprocess could actually read, which is the property that keeps this check
// in the engine rather than in workflow shell.
package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	blackboxTrustedKey = "-----BEGIN PUBLIC KEY-----\nblackbox-trusted-release-key\n-----END PUBLIC KEY-----\n"
	blackboxOtherKey   = "-----BEGIN PUBLIC KEY-----\nblackbox-some-other-key\n-----END PUBLIC KEY-----\n"
)

// signingKeyFixture writes the trusted anchor plus a cosign stand-in that
// derives derivedKey, and returns the working directory and the anchor path.
func signingKeyFixture(t *testing.T, trustedKey, derivedKey string) (dir, anchor, fakeBin string) {
	t.Helper()

	dir = t.TempDir()
	anchor = filepath.Join(dir, "cosign.pub")

	if err := os.WriteFile(anchor, []byte(trustedKey), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeBin = t.TempDir()
	writeFakeTool(t, fakeBin, "cosign", `case "${1:-}" in
  version) echo 'fake cosign v0'; exit 0 ;;
  public-key)
    [ -n "${COSIGN_KEY:-}" ] || { echo 'fake cosign: no key in env' >&2; exit 1; }
    printf '%s' `+shellQuote(derivedKey)+`
    exit 0
    ;;
esac
echo 'fake cosign: unexpected invocation' >&2
exit 1
`)

	return dir, anchor, fakeBin
}

func signingKeyEnv(fakeBin string, extra map[string]string) map[string]string {
	env := map[string]string{
		"PATH":       fakeBin + string(os.PathListSeparator) + suitePATH(),
		"COSIGN_KEY": "private-key-material-DO-NOT-LOG",
	}
	for name, value := range extra {
		env[name] = value
	}

	return env
}

// The key the project trusts is accepted, and the operator is told which
// digest matched rather than being shown either key.
func TestValidateSigningKey_AcceptsTheTrustedKey(t *testing.T) {
	dir, anchor, fakeBin := signingKeyFixture(t, blackboxTrustedKey, blackboxTrustedKey)

	stdout, stderr, code := run(t, runOpts{dir: dir, env: signingKeyEnv(fakeBin, nil)},
		"validate", "signing-key", "--key", "env://COSIGN_KEY", "--trusted-public-key", anchor)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "matches the trusted public key") {
		t.Errorf("stdout does not confirm the match: %q", stdout)
	}
}

// A well-formed key that is simply not this project's key is refused as a rule
// failure, and the refusal names both digests so an operator can tell which
// key arrived.
func TestValidateSigningKey_RejectsADifferentKey(t *testing.T) {
	dir, anchor, fakeBin := signingKeyFixture(t, blackboxTrustedKey, blackboxOtherKey)

	stdout, stderr, code := run(t, runOpts{dir: dir, env: signingKeyEnv(fakeBin, nil)},
		"validate", "signing-key", "--key", "env://COSIGN_KEY", "--trusted-public-key", anchor)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d (key rejected by a check)\nstderr: %s", code, exitValidation, stderr)
	}

	if !strings.Contains(stderr, "trusted public-key sha256") || !strings.Contains(stderr, "derived public-key sha256") {
		t.Errorf("refusal does not name both digests: %s", stderr)
	}

	if stdout != "" {
		t.Errorf("rejected key still produced stdout: %q", stdout)
	}
}

// Neither outcome may put key material on a stream a CI log captures. The
// private material is what the stand-in was given; the public halves are what
// it printed.
func TestValidateSigningKey_LeaksNoKeyMaterial(t *testing.T) {
	for name, derived := range map[string]string{
		"match":    blackboxTrustedKey,
		"mismatch": blackboxOtherKey,
	} {
		t.Run(name, func(t *testing.T) {
			dir, anchor, fakeBin := signingKeyFixture(t, blackboxTrustedKey, derived)

			stdout, stderr, _ := run(t, runOpts{dir: dir, env: signingKeyEnv(fakeBin, nil)},
				"validate", "signing-key", "--key", "env://COSIGN_KEY", "--trusted-public-key", anchor)

			for _, secret := range []string{
				"private-key-material-DO-NOT-LOG",
				"blackbox-trusted-release-key",
				"blackbox-some-other-key",
				"BEGIN PUBLIC KEY",
			} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("output leaked %q\nstdout: %s\nstderr: %s", secret, stdout, stderr)
				}
			}
		})
	}
}

// Swapping the trust anchor must not be a way to make any key pass: with a
// recorded digest present, an anchor that no longer matches it is refused
// before it is used as the comparison target.
func TestValidateSigningKey_RejectsATamperedTrustAnchor(t *testing.T) {
	dir, anchor, fakeBin := signingKeyFixture(t, blackboxOtherKey, blackboxOtherKey)

	// The sidecar still records the digest of the key that was trusted
	// before the swap, so it is computed from that key's bytes.
	original := filepath.Join(t.TempDir(), "original.pub")
	if err := os.WriteFile(original, []byte(blackboxTrustedKey), 0o600); err != nil {
		t.Fatal(err)
	}

	digest := filepath.Join(dir, "cosign.pub.sha256")
	if err := os.WriteFile(digest, []byte(sha256File(t, original)+"  cosign.pub\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: dir, env: signingKeyEnv(fakeBin, nil)},
		"validate", "signing-key", "--key", "env://COSIGN_KEY",
		"--trusted-public-key", anchor, "--trusted-public-key-digest", digest)
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d (anchor lost its recorded digest)\nstderr: %s", code, exitValidation, stderr)
	}

	if !strings.Contains(stderr, "recorded digest") {
		t.Errorf("refusal does not explain the anchor mismatch: %s", stderr)
	}
}

// The reason this check belongs in the engine: the cosign subprocess that
// touches the signing key sees only the runtime environment plus the key
// variable and COSIGN_PASSWORD. A shell implementation cannot make that
// promise, because every later step in the job inherits what it exports.
func TestValidateSigningKey_IsolatesTheCosignSubprocess(t *testing.T) {
	dir, anchor, fakeBin := signingKeyFixture(t, blackboxTrustedKey, blackboxTrustedKey)

	seen := filepath.Join(t.TempDir(), "child-env.txt")
	writeFakeTool(t, fakeBin, "cosign", `case "${1:-}" in
  version) echo 'fake cosign v0'; exit 0 ;;
  public-key)
    printf 'AMBIENT=%s\nKEY=%s\nPASSWORD=%s\n' \
      "${AMBIENT_MUST_NOT_REACH_COSIGN:-absent}" "${COSIGN_KEY:+present}" "${COSIGN_PASSWORD:-absent}" \
      >`+shellQuote(seen)+`
    printf '%s' `+shellQuote(blackboxTrustedKey)+`
    exit 0
    ;;
esac
exit 1
`)

	_, stderr, code := run(t, runOpts{dir: dir, env: signingKeyEnv(fakeBin, map[string]string{
		"AMBIENT_MUST_NOT_REACH_COSIGN": "ambient-secret",
		"COSIGN_PASSWORD":               "key-passphrase",
	})}, "validate", "signing-key", "--key", "env://COSIGN_KEY", "--trusted-public-key", anchor)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr)
	}

	body, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("cosign stand-in recorded nothing: %v", err)
	}

	childEnv := string(body)
	if !strings.Contains(childEnv, "AMBIENT=absent") {
		t.Errorf("an ambient secret reached the cosign subprocess: %s", childEnv)
	}

	// The isolation must not be so aggressive that signing stops working:
	// the key and its passphrase are exactly what cosign still needs.
	if !strings.Contains(childEnv, "KEY=present") || !strings.Contains(childEnv, "PASSWORD=key-passphrase") {
		t.Errorf("isolation withheld the key material cosign needs: %s", childEnv)
	}
}
