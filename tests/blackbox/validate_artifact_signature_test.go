// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
//go:build blackbox

// Keyless verify-identity derivation. A full keyless roundtrip needs a
// real OIDC/Fulcio environment, which CI can't provide, so this is a
// low-fidelity check: in a faked-forge environment, `validate
// artifact-signature` on a .bundle must DERIVE the certificate identity
// from the forge rather than demand --cert-identity-regexp. The engine
// redacts the failing argv down to "cosign verify-blob" in its own
// error, so the derivation is observed where it actually lands: a
// recording cosign stand-in on PATH captures the argv the engine built.
package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateArtifactSignature_KeylessIdentityDerivedFromForge(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "app.tgz")
	if err := os.WriteFile(art, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A dummy bundle: auto-detection sees .bundle and picks the
	// sigstore-bundle verify path.
	if err := os.WriteFile(art+".bundle", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The recording stand-in: logs every invocation's argv, then rejects
	// like a real cosign facing an unverifiable bundle. Version probes
	// succeed so tool detection cannot mistake it for an absent cosign.
	fakeBin := t.TempDir()
	argvLog := filepath.Join(t.TempDir(), "cosign-argv.log")
	writeFakeTool(t, fakeBin, "cosign", `printf 'cosign %s\n' "$*" >>`+shellQuote(argvLog)+`
case "${1:-}" in
  version) echo 'fake cosign v0'; exit 0 ;;
esac
echo 'fake cosign: bundle rejected' >&2
exit 1
`)

	_, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"PATH":              fakeBin + string(os.PathListSeparator) + suitePATH(),
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "fixture/integration",
		"GITHUB_SERVER_URL": "https://github.com",
	}}, "validate", "artifact-signature", "--artifact", art, "--method", "sigstore")

	// The two outcomes are cleanly separable: broken derivation dies
	// before cosign with exit 2 and "cert-identity-regexp is empty";
	// working derivation reaches the cosign subprocess, whose rejection
	// the engine classifies as a rule failure (ErrValidation, exit 1)
	// wrapped as "artifact cosign verification failed".
	if code != exitValidation {
		t.Fatalf("exit = %d, want 1 (cosign reached, rejection classified as validation)\nstderr: %s", code, stderr)
	}

	if strings.Contains(stderr, "cert-identity-regexp is empty") {
		t.Errorf("identity was not derived from the forge:\n%s", stderr)
	}

	assertContains(t, "surfaces the cosign rejection", stderr, "artifact cosign verification failed")

	// The derivation, made visible: the recorded cosign argv must carry an
	// identity constraint anchored to the repository from the forge env,
	// and the forge's OIDC issuer — neither was passed as a flag above.
	// Both halves must be in the SAME invocation. The log holds one line per
	// cosign call (the version probe as well as the verify), so asserting the
	// flag appears somewhere and the repository appears somewhere would be
	// satisfied by two unrelated lines — the claim is that this verify call
	// carries a repo-anchored identity.
	argv := readFile(t, argvLog)

	var identityLine string

	for line := range strings.SplitSeq(argv, "\n") {
		if strings.Contains(line, "--certificate-identity-regexp") {
			identityLine = line

			break
		}
	}

	if identityLine == "" {
		t.Errorf("no cosign invocation carried --certificate-identity-regexp; got:\n%s", argv)
	} else {
		if !strings.Contains(identityLine, "fixture/integration") {
			t.Errorf("--certificate-identity-regexp is not anchored to the forge repository; got:\n%s", identityLine)
		}

		if !strings.Contains(identityLine, "--certificate-oidc-issuer https://token.actions.githubusercontent.com") {
			t.Errorf("expected the forge-derived OIDC issuer in the same cosign invocation; got:\n%s", identityLine)
		}
	}
}
