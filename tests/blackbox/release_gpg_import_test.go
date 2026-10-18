// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the secret-handling hardening:
//
//   - GPG key flows via stdin, never lands on disk in our tmpdir
//   - Subprocess errors don't echo private-key markers
//   - Process-level hardening doesn't break the happy path

package blackbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurity_GPGImportLeavesNoKeyResidue runs a full `release gpg
// import` cycle and asserts the temporary directory it touched
// contains no files whose name or contents suggest private-key material.
//
// TestSecurity_KeyResidueScanFindsPlantedResidue is the positive control that
// proves the scanner detects both key-like names and key markers.
func TestSecurity_GPGImportLeavesNoKeyResidue(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	// Isolated TMPDIR so the assertion below is meaningful. The
	// forge-ci binary will use this for any os.MkdirTemp calls;
	// any residue lands here.
	tmp := t.TempDir()

	// --git-config-global=false keeps any git config the import writes in
	// repository scope, and the scratch dir keeps that scope out of the
	// suite's own checkout.
	env := key.signingEnv(t)
	env["TMPDIR"] = tmp

	_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: env},
		"release", "gpg", "import", "--git-config-global=false")
	if code != 0 {
		t.Fatalf("release gpg import exit %d\nstderr: %s", code, stderr)
	}

	// Today the import streams the key over stdin and never writes TMPDIR,
	// so this is a tripwire: a later temp-file path must still leave nothing.

	suspicious := keyResidueIn(t, tmp)
	if len(suspicious) > 0 {
		t.Errorf("found %d suspicious file(s) in TMPDIR after `release gpg import` — the key may have hit disk:\n%s",
			len(suspicious), strings.Join(suspicious, "\n"))
	}
}

// TestSecurity_GPGStderrDoesNotEchoInputKey forces a gpg failure on
// a malformed key and asserts the wrapped error reaching our stderr
// has NO recognisable private-key marker in it. The redactor in
// internal/safeexec/redact.go is the safety net.
func TestSecurity_GPGStderrDoesNotEchoInputKey(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")

	tmp := t.TempDir()

	// Pass a deliberately-malformed key that contains a private-key
	// marker. If gpg ever decided to echo input on error, our
	// redactor must catch it before the bytes leave the process.
	malformed := "-----BEGIN PGP PRIVATE KEY BLOCK-----\nthis-is-not-base64-armor-payload\n-----END PGP PRIVATE KEY BLOCK-----\n"

	_, stderr, code := run(t, runOpts{
		env: map[string]string{
			"GNUPGHOME":       t.TempDir(), // isolated empty
			"GPG_PRIVATE_KEY": malformed,
			"TMPDIR":          tmp,
		},
	}, "release", "gpg", "import")

	if code == 0 {
		t.Fatal("malformed key should fail gpg --import")
	}

	// The redactor replaces the body with a notice; the marker may
	// still appear in the replacement text. What MUST NOT appear is
	// the original payload bytes ("this-is-not-base64-armor-payload").
	if strings.Contains(stderr, "this-is-not-base64-armor-payload") {
		t.Errorf("stderr leaked the original input-key payload:\n%s", stderr)
	}

	// An empty stderr would satisfy the check above while telling the operator
	// nothing. The failure has to still be reported — redaction that swallowed
	// the whole diagnostic would be a different regression passing as this one.
	assertContains(t, "import failure is still reported", stderr, "gpg --import")
	assertContains(t, "redaction is named, not silent", stderr, "diagnostics suppressed")
}

// keyResidueIn reports files under dir that look like private-key material,
// by name or by content.
func keyResidueIn(t *testing.T, dir string) []string {
	t.Helper()

	var suspicious []string

	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		name := strings.ToLower(filepath.Base(path))
		switch {
		case strings.Contains(name, "key"),
			strings.HasSuffix(name, ".pgp"),
			strings.HasSuffix(name, ".asc"),
			strings.HasSuffix(name, ".gpg"):
			suspicious = append(suspicious, path)
		}

		// Names can lie: a residue file with an innocuous temp name would
		// slip the switch above. The key went in as armored ASCII, so any
		// file carrying its marker is the key on disk, whatever it is called.
		if body, readErr := os.ReadFile(path); readErr == nil &&
			strings.Contains(string(body), "PGP PRIVATE KEY BLOCK") {
			suspicious = append(suspicious, path+" (contains private-key marker)")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}

	return suspicious
}

// TestSecurity_KeyResidueScanFindsPlantedResidue is the positive control for
// the residue test. That test's TMPDIR is empty on a passing run, so its zero
// is only evidence if the scanner would have found a residue had one been
// there — both the obvious kind and the kind that hides behind an innocuous
// temp name.
func TestSecurity_KeyResidueScanFindsPlantedResidue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Clean to begin with, matching the state the real test observes.
	if got := keyResidueIn(t, dir); len(got) != 0 {
		t.Fatalf("fixture is not clean: %v", got)
	}

	named := filepath.Join(dir, "key.asc")
	if err := os.WriteFile(named, []byte("anything"), 0o600); err != nil {
		t.Fatal(err)
	}

	// An innocuous name — what a real os.MkdirTemp residue would look like.
	hidden := filepath.Join(dir, "tmp1234")
	if err := os.WriteFile(hidden, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	found := strings.Join(keyResidueIn(t, dir), "\n")

	if !strings.Contains(found, named) {
		t.Errorf("scanner missed a key-named residue; found:\n%s", found)
	}

	if !strings.Contains(found, hidden) {
		t.Errorf("scanner missed a private-key marker under an innocuous name; found:\n%s", found)
	}
}
