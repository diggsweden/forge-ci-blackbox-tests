// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import "testing"

func TestSigningPrivacyRefusesBeforeCredentialsOrNetwork(t *testing.T) {
	for _, tc := range []struct {
		name, visibility, method, transparency string
		code                                   int
	}{
		{"private implicit", "private", "sigstore", "", exitConfig},
		{"unknown implicit", "unknown", "kms", "", exitConfig},
		{"public default", "public", "sigstore", "", 0},
		{"private explicit", "private", "sigstore", "public", 0},
		{"private no log", "private", "kms", "none", 0},
		{"keyless no log", "private", "sigstore", "none", exitConfig},
		{"private gpg", "private", "gpg", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "validate", "signing-privacy", "--repository-visibility", tc.visibility, "--method", tc.method, "--transparency", tc.transparency)
			if code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, stderr)
			}
		})
	}
}
