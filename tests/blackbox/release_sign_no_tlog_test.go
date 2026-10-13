// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Containment: this suite drives the REAL cosign binary, and cosign uploads to
// the public Rekor transparency log by default. A Rekor entry is permanent,
// public, and append-only — a test run cannot take one back. So the suite must
// never sign against the public Sigstore config.
//
// forge-ci exposes $FORGE_CI_COSIGN_TRANSPARENCY=none for this — the
// same setting an internal-only consumer reaches for via `sign.transparency`
// in artifacts.yml, so the suite exercises the real path rather than a
// test-only escape hatch. cosign's own --tlog-upload=false is deprecated in 3.x
// and errors out, so the engine materialises a signing config naming no
// transparency-log service, which is the supported route.
//
// These tests assert the containment holds against the actual binary, not just
// in the adapter's argv.

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// tlogEntryCount reports how many transparency-log entries a cosign bundle
// carries. Zero means nothing was published.
func tlogEntryCount(t *testing.T, bundlePath string) int {
	t.Helper()

	var bundle struct {
		VerificationMaterial struct {
			TlogEntries []json.RawMessage `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}

	if err := json.Unmarshal([]byte(readFile(t, bundlePath)), &bundle); err != nil {
		t.Fatalf("parse cosign bundle %s: %v", bundlePath, err)
	}

	return len(bundle.VerificationMaterial.TlogEntries)
}

// TestReleaseSign_PublishesNoTlogEntry is the containment test: with the
// engine's signing config pointed at a no-transparency-log Sigstore config, a
// real `release sign --method=kms` must produce a bundle carrying zero Rekor
// entries.
//
// Without the config this same path writes a real entry to the public log —
// verified against cosign 3.1.1 — so this test is what keeps the suite (and
// forgejo-ci's vendor gate, which runs it on every re-vendor) from publishing
// on every run.
func TestReleaseSign_PublishesNoTlogEntry(t *testing.T) {
	requireTool(t, "cosign")

	dir := t.TempDir()
	priv, _ := cosignKey(t, dir)

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("archive payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No signing-config is set here on purpose: isolatedEnv supplies it to
	// every invocation, and this asserts that suite-wide containment holds.
	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{"COSIGN_PASSWORD": ""},
	}, "release", "sign",
		"--release-artifacts-dir", "release-artifacts",
		"--method", "kms", "--key", priv)
	if code != 0 {
		t.Fatalf("release sign exit=%d stderr=%s", code, stderr)
	}

	bundle := filepath.Join(dir, "app.tgz.bundle")
	if !fileExists(bundle) {
		t.Fatalf("expected a cosign bundle at %s", bundle)
	}

	if n := tlogEntryCount(t, bundle); n != 0 {
		t.Errorf("bundle carries %d transparency-log entr(y/ies): the signature was published "+
			"to the public Rekor log. Rekor is append-only, so this cannot be undone. "+
			"$%s=none should have prevented it.", n, "FORGE_CI_COSIGN_TRANSPARENCY")
	}
}

// TestTlogEntryCount_SeesEntriesWhenPresent is the positive control for the
// containment test above, and it exists because that test can only ever assert
// a ZERO.
//
// tlogEntryCount decodes one field path. If cosign renames it, or the bundle
// schema moves, json.Unmarshal still succeeds, TlogEntries stays nil, and the
// containment test reports "0 entries" — passing at full confidence while
// having stopped looking. For a check whose entire job is to prevent an
// irreversible publication to a public append-only log, a counter that cannot
// be shown to count is not evidence.
//
// A real bundle carrying entries cannot be produced here without publishing to
// Rekor, which is the exact thing the suite must never do — so the control is
// on the parser: hand it the documented shape and require the count.
func TestTlogEntryCount_SeesEntriesWhenPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"no entries", `{"verificationMaterial":{"tlogEntries":[]}}`, 0},
		{"one entry", `{"verificationMaterial":{"tlogEntries":[{"logIndex":"1"}]}}`, 1},
		{"two entries", `{"verificationMaterial":{"tlogEntries":[{"logIndex":"1"},{"logIndex":"2"}]}}`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "bundle-"+tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			if got := tlogEntryCount(t, path); got != tc.want {
				t.Errorf("tlogEntryCount = %d, want %d — the containment test's zero is not evidence", got, tc.want)
			}
		})
	}
}
