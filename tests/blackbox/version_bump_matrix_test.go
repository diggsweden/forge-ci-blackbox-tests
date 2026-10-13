// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionBump_WritesVersionOfRecordAcrossEcosystems is the comprehensive happy-path coverage for
// `version bump` across every supported project type. One sub-test
// per ecosystem; each materialises a minimal valid manifest, runs
// the bump, and asserts that the version-of-record landed in the
// expected file. Idempotence is rechecked.
//
// Subtests that depend on an external CLI (mvn for Maven, npm for
// NPM) skip when that CLI is missing, instead of failing in
// CI-unfriendly ways.
func TestVersionBump_WritesVersionOfRecordAcrossEcosystems(t *testing.T) {
	t.Run("maven_single_module", func(t *testing.T) {
		requireTool(t, "mvn")

		proj := copyTree(t, fixture("maven-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "maven", "--version", "5.0.0",
			"--maven-cli-opts", "-B -ntp",
		)
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		// The project's own <version>, not any dependency or plugin version.
		var pom struct {
			Version string `xml:"version"`
		}
		if err := xml.Unmarshal([]byte(readFile(t, filepath.Join(proj, "pom.xml"))), &pom); err != nil {
			t.Fatalf("parse pom.xml: %v", err)
		}

		if pom.Version != "5.0.0" {
			t.Errorf("pom.xml project version = %q, want 5.0.0", pom.Version)
		}
	})

	t.Run("npm_simple", func(t *testing.T) {
		requireTool(t, "npm")

		proj := copyTree(t, fixture("npm-lib"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "npm", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		var pkg struct {
			Version string `json:"version"`
		}
		decodeJSON(t, "package.json", readFile(t, filepath.Join(proj, "package.json")), &pkg)

		if pkg.Version != "5.0.0" {
			t.Errorf("package.json version = %q, want 5.0.0", pkg.Version)
		}
	})

	t.Run("gradle_jvm", func(t *testing.T) {
		proj := copyTree(t, fixture("gradle-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "gradle.properties", readFile(t, filepath.Join(proj, "gradle.properties")), "version=5.0.0")
	})

	t.Run("gradle_android", func(t *testing.T) {
		proj := copyTree(t, fixture("gradle-android-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle-android", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		body := readFile(t, filepath.Join(proj, "gradle.properties"))
		assertContains(t, "gradle.properties", body, "versionName=5.0.0")
		// versionCode is auto-incremented from 42 → 43.
		assertContains(t, "gradle.properties", body, "versionCode=43")
	})

	t.Run("cargo_workspace", func(t *testing.T) {
		requireTool(t, "cargo")

		proj := copyTree(t, fixture("cargo-workspace"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "cargo", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "Cargo.toml", readFile(t, filepath.Join(proj, "Cargo.toml")), `version = "5.0.0"`)
	})

	t.Run("cargo_single_crate", func(t *testing.T) {
		requireTool(t, "cargo")

		proj := copyTree(t, fixture("cargo-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "cargo", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "Cargo.toml", readFile(t, filepath.Join(proj, "Cargo.toml")), `version = "5.0.0"`)
	})

	t.Run("xcode_ios", func(t *testing.T) {
		dir := t.TempDir()

		// xcode bump writes versions.xcconfig if missing; demonstrate both
		// shapes in one test by pre-creating the file.
		xc := filepath.Join(dir, "versions.xcconfig")
		if err := os.WriteFile(xc, []byte("MARKETING_VERSION = 0.1.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "xcode-ios", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "versions.xcconfig", readFile(t, xc), "MARKETING_VERSION = 5.0.0")
	})

	t.Run("go_is_noop", func(t *testing.T) {
		// Go has no version-of-record file — version comes from ldflags.
		// Bump must exit 0 with an informational message; nothing should
		// be modified on disk. The "✓" line goes to stderr (logger sink),
		// not stdout.
		proj := copyTree(t, fixture("go-hello"))
		preMod := readFile(t, filepath.Join(proj, "go.mod"))

		_, stderr, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "go", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		if readFile(t, filepath.Join(proj, "go.mod")) != preMod {
			t.Errorf("go.mod unexpectedly modified by no-op bump")
		}

		assertContains(t, "stderr", stderr, "ldflags")
	})

	t.Run("meta_is_noop", func(t *testing.T) {
		// Meta projects (changelog-only artifacts) accept a bump for the
		// changelog version-of-record but write no file.
		dir := t.TempDir()

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "meta", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "stderr", stderr, "changelog")
	})
}

// TestVersionBump_SameVersionTwiceIsIdempotent verifies that bumping to the SAME
// version twice in a row is a clean no-op (exit 0, file unchanged).
// CI sometimes retries the bump step; non-idempotent bumps would
// produce confusing "version already at X" hard-failures.
//
// Note: gradle-android is intentionally excluded. Its bump always
// increments versionCode (Play Store requires monotonic increase),
// so two bumps to the SAME versionName still mutate the file. That
// is correct behaviour — the test framework would just misread it
// as a regression.
func TestVersionBump_SameVersionTwiceIsIdempotent(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		ptype   string
		path    string
	}{
		{name: "gradle", fixture: "gradle-hello", ptype: "gradle", path: "gradle.properties"},
		{name: "cargo", fixture: "cargo-workspace", ptype: "cargo", path: "Cargo.toml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.ptype == "cargo" {
				requireTool(t, "cargo")
			}

			proj := copyTree(t, fixture(tc.fixture))

			args := []string{"version", "bump", "--project-type", tc.ptype, "--version", "7.7.7"}

			if _, _, code := run(t, runOpts{dir: proj}, args...); code != 0 {
				t.Fatalf("first bump exit %d", code)
			}

			afterFirst := readFile(t, filepath.Join(proj, tc.path))

			if _, _, code := run(t, runOpts{dir: proj}, args...); code != 0 {
				t.Errorf("second bump exit %d (idempotence)", code)
			}

			afterSecond := readFile(t, filepath.Join(proj, tc.path))

			if afterFirst != afterSecond {
				t.Errorf("bump is not idempotent for %s:\nfirst:\n%s\nsecond:\n%s",
					tc.ptype, afterFirst, afterSecond)
			}
		})
	}
}

// TestVersionBump_EdgeCaseExitCodes covers the error paths CI policy depends
// on. Each scenario asserts the documented exit code AND the message naming
// the rule, since several rules share a code.
func TestVersionBump_EdgeCaseExitCodes(t *testing.T) {
	t.Run("missing_gradle_properties_is_no_input", func(t *testing.T) {
		dir := t.TempDir()

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "gradle", "--version", "1.0.0")
		if code != exitNoInput {
			t.Errorf("missing gradle.properties: exit %d, want 66 (EX_NOINPUT) — a missing input "+
				"file is an input problem, not an internal-software one\nstderr: %s", code, stderr)
		}

		assertContains(t, "missing gradle.properties", stderr, "Gradle version file not found")
	})

	t.Run("missing_required_flag_is_USAGE", func(t *testing.T) {
		dir := t.TempDir()

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "gradle")
		if code != exitUsage {
			t.Errorf("expected EX_USAGE=2 when --version omitted; got %d", code)
		}

		assertContains(t, "missing --version", stderr, `Required flag "version" not set`)
	})

	t.Run("unknown_project_type_is_USAGE", func(t *testing.T) {
		dir := t.TempDir()

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "rust-lang", "--version", "1.0.0")
		if code != exitUsage {
			t.Errorf("expected EX_USAGE=2 for unknown project type; got %d", code)
		}

		assertContains(t, "unknown project type", stderr, "unknown project type: rust-lang")
	})

	t.Run("malformed_cargo_toml_fails", func(t *testing.T) {
		requireTool(t, "cargo")

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("not valid toml [[[\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "cargo", "--version", "1.0.0")
		if code != exitValidation {
			t.Errorf("malformed Cargo.toml: exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
		}

		// Name the parse rule so an unrelated failure cannot satisfy the case.
		assertContains(t, "malformed Cargo.toml", stderr,
			"neither [package] nor [workspace.package]")
	})

	t.Run("leading_v_in_version_is_canonicalized", func(t *testing.T) {
		// The CLI help promises "--version takes a bare semver (without
		// a leading 'v')". The engine canonicalizes rather than rejects:
		// a semver-valid "v1.2.3" is accepted and gradle.properties
		// records the bare 1.2.3; the v-prefixed spelling never reaches the file.
		proj := copyTree(t, fixture("gradle-hello"))

		_, stderr, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle", "--version", "v1.2.3")
		if code != 0 {
			t.Fatalf("bump with v-prefixed semver exit %d\nstderr: %s", code, stderr)
		}

		body := readFile(t, filepath.Join(proj, "gradle.properties"))
		if !strings.Contains(body, "version=1.2.3") {
			t.Errorf("expected gradle.properties to record the canonical 1.2.3; got:\n%s", body)
		}

		if strings.Contains(body, "version=v1.2.3") {
			t.Errorf("v-prefixed version leaked into gradle.properties verbatim:\n%s", body)
		}
	})
}
