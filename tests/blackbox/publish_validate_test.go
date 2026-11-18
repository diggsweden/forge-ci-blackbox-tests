// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the LOCAL-ONLY `publish` verbs — the
// preparation/validation steps that run before any registry is touched.
// The real deploy verbs (npm publish, maven-central deploy, appstore /
// google-play upload) need live stores and stay out of scope; these do
// not — they write an .npmrc, stat a tarball, or walk a target/ tree.
//
// The load-bearing case is write-npmrc's secret hygiene: it must emit the
// literal ${NODE_AUTH_TOKEN} placeholder and never interpolate the real
// token, so a token in the environment can never leak into the file or
// the logs.

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublishNPMWriteNPMRC_ScopedBodyAndPerms asserts the exact 2-line
// scoped .npmrc, the literal token placeholder, and the 0600 mode.
func TestPublishNPMWriteNPMRC_ScopedBodyAndPerms(t *testing.T) {
	t.Parallel()

	proj := t.TempDir()

	_, stderr, code := run(t, runOpts{dir: proj},
		"publish", "npm", "write-npmrc",
		"--registry", "https://registry.npmjs.org",
		"--scope", "@fixture",
		"--output", ".npmrc")
	if code != 0 {
		t.Fatalf("write-npmrc exit %d\nstderr: %s", code, stderr)
	}

	npmrc := filepath.Join(proj, ".npmrc")

	body := readFile(t, npmrc)
	for _, line := range []string{
		"//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}",
		"@fixture:registry=https://registry.npmjs.org",
	} {
		assertContains(t, ".npmrc", body, line)
	}

	// always-auth must NOT be written. npm dropped it from the CLI in 7.11.1
	// (2021) and current npm reports it as an unknown config, warning it will
	// stop working outright in the next major -- so emitting it printed a
	// deprecation warning on every publish for a line that did nothing. The
	// path-scoped _authToken above is what authenticates. This asserts the
	// absence so the line cannot creep back in.
	if strings.Contains(body, "always-auth") {
		t.Errorf(".npmrc must not set always-auth (removed from npm in 7.11.1); got:\n%s", body)
	}

	if fi, err := os.Stat(npmrc); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf(".npmrc mode %o, want 0600 (it names a credential file)", perm)
	}
}

// TestPublishNPMWriteNPMRC_NeverInterpolatesToken is the security
// assertion: a NODE_AUTH_TOKEN in the environment must not appear in the
// written file or on stdout/stderr — the command emits a placeholder that
// npm expands at publish time, it never reads the secret itself.
func TestPublishNPMWriteNPMRC_NeverInterpolatesToken(t *testing.T) {
	t.Parallel()

	const secret = "supersecret-should-not-appear"

	proj := t.TempDir()

	stdout, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{"NODE_AUTH_TOKEN": secret},
	},
		"publish", "npm", "write-npmrc",
		"--registry", "https://registry.npmjs.org",
		"--output", ".npmrc")
	if code != 0 {
		t.Fatalf("write-npmrc exit %d\nstderr: %s", code, stderr)
	}

	body := readFile(t, filepath.Join(proj, ".npmrc"))
	for label, hay := range map[string]string{".npmrc": body, "stdout": stdout, "stderr": stderr} {
		if strings.Contains(hay, secret) {
			t.Errorf("%s leaked the NODE_AUTH_TOKEN value; it must stay a ${...} placeholder", label)
		}
	}

	// The unscoped body carries a plain registry= line, not @scope:registry=.
	assertContains(t, ".npmrc", body, "registry=https://registry.npmjs.org")
	assertContains(t, ".npmrc", body, "${NODE_AUTH_TOKEN}")
}

// TestPublishNPMWriteNPMRC_RejectsUnsafeRegistry pins the URL policy:
// plaintext http to a non-loopback host, and non-https schemes, are
// EX_USAGE (2); loopback http is allowed (dev registries).
func TestPublishNPMWriteNPMRC_RejectsUnsafeRegistry(t *testing.T) {
	t.Parallel()

	// Every refusal here exits 2, so the code alone cannot tell which rule
	// fired — a row could pass on a neighbour's rule. Each refusing row pins
	// the sentence that names its own.
	cases := []struct {
		name     string
		registry string
		extra    []string
		want     int
		wantErr  string
	}{
		{"plaintext_http_nonloopback", "http://registry.npmjs.org", nil, 2, "uses plaintext http"},
		{"non_https_scheme", "ftp://registry.npmjs.org", nil, 2, `scheme "ftp" must be https`},
		{"bad_scope", "https://registry.npmjs.org", []string{"--scope", "NoAtSign"}, 2, `scope "NoAtSign" is not a valid npm scope`},

		// All three loopback spellings are allowed, not just the word
		// "localhost": 127.0.0.1 is the form a CI service container usually
		// gets, and [::1] the one a v6-only runner does. Rejecting either
		// would push people to plaintext-http workarounds elsewhere.
		{"loopback_http_allowed", "http://localhost:4873", nil, 0, ""},
		{"loopback_ipv4_http_allowed", "http://127.0.0.1:4873", nil, 0, ""},
		{"loopback_ipv6_http_allowed", "http://[::1]:4873", nil, 0, ""},

		// The near miss, and the reason the allowed forms above are worth
		// pinning: a host that merely STARTS with "localhost" is not loopback.
		// A prefix match here would hand an npm auth token to an
		// attacker-controlled host over plaintext http.
		{"loopback_lookalike_refused", "http://localhost.evil.example:4873", nil, 2, "uses plaintext http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"publish", "npm", "write-npmrc", "--registry", tc.registry, "--output", "-"}, tc.extra...)

			_, stderr, code := run(t, runOpts{dir: t.TempDir()}, args...)
			if code != tc.want {
				t.Errorf("%s: exit %d, want %d\nstderr: %s", tc.name, code, tc.want, stderr)
			}

			if tc.wantErr != "" {
				assertContains(t, tc.name, stderr, tc.wantErr)
			}
		})
	}
}

// TestPublishNPMValidateTarball_RequiresDistCLI drives the real npm-pack → validate cycle:
// the verb finds the tarball, extracts it (stripping npm's package/
// prefix), deletes it, and requires dist/cli.js to exist.
func TestPublishNPMValidateTarball_RequiresDistCLI(t *testing.T) {
	requireTool(t, "npm")

	t.Run("passes_when_dist_cli_present", func(t *testing.T) {
		proj := copyTree(t, fixture("npm-lib"))

		if err := os.MkdirAll(filepath.Join(proj, "dist"), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(proj, "dist", "cli.js"), []byte("console.log('hi')\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		if _, stderr, code := runTool(t, proj, "npm", "pack"); code != 0 {
			t.Fatalf("npm pack: %s", stderr)
		}

		_, stderr, code := run(t, runOpts{dir: proj}, "publish", "npm", "validate-tarball")
		if code != 0 {
			t.Fatalf("validate-tarball exit %d\nstderr: %s", code, stderr)
		}

		// The tarball is consumed (extracted then deleted) and dist/cli.js
		// survives the round-trip.
		if tgz := globMust(proj, "*.tgz"); len(tgz) != 0 {
			t.Errorf("tarball should have been consumed, still present: %v", tgz)
		}

		if !fileExists(filepath.Join(proj, "dist", "cli.js")) {
			t.Errorf("dist/cli.js missing after extraction")
		}
	})

	t.Run("fails_when_dist_cli_missing", func(t *testing.T) {
		// npm-lib has no dist/cli.js — pack it as-is.
		proj := copyTree(t, fixture("npm-lib"))

		if _, stderr, code := runTool(t, proj, "npm", "pack"); code != 0 {
			t.Fatalf("npm pack: %s", stderr)
		}

		_, stderr, code := run(t, runOpts{dir: proj}, "publish", "npm", "validate-tarball")
		if code != exitValidation {
			t.Fatalf("validate-tarball exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
		}

		assertContains(t, "stderr", stderr, "NOT found")
	})

	t.Run("no_tarball_is_no_input", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "publish", "npm", "validate-tarball")
		if code != exitNoInput {
			t.Fatalf("no tarball: exit %d, want 66 (EX_NOINPUT)\nstderr: %s", code, stderr)
		}

		assertContains(t, "stderr", stderr, "No tarball")
	})
}

// touchJar creates an empty stub jar at <dir>/<rel>, making parents.
func touchJar(t *testing.T, dir, rel string) {
	t.Helper()

	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(abs, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPublishMavenCentralValidateArtifacts_RequiresSourcesAndJavadoc walks target/ trees and
// requires at least one sources JAR and one javadoc JAR — Maven Central's
// hard publishing requirement. Pure filesystem, no mvn/network.
func TestPublishMavenCentralValidateArtifacts_RequiresSourcesAndJavadoc(t *testing.T) {
	t.Parallel()

	run3 := func(t *testing.T, dir string) (string, int) {
		t.Helper()
		_, stderr, code := run(t, runOpts{dir: dir}, "publish", "maven-central", "validate-artifacts")

		return stderr, code
	}

	t.Run("passes_with_sources_and_javadoc", func(t *testing.T) {
		dir := t.TempDir()
		touchJar(t, dir, "target/app-1.0.0.jar")
		touchJar(t, dir, "target/app-1.0.0-sources.jar")
		touchJar(t, dir, "target/app-1.0.0-javadoc.jar")

		stderr, code := run3(t, dir)
		if code != 0 {
			t.Fatalf("exit %d, want 0\nstderr: %s", code, stderr)
		}

		assertContains(t, "stderr", stderr, "All required artifacts present")
	})

	t.Run("missing_sources_is_validation", func(t *testing.T) {
		dir := t.TempDir()
		touchJar(t, dir, "target/app-1.0.0-javadoc.jar")

		stderr, code := run3(t, dir)
		if code != exitValidation {
			t.Fatalf("exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
		}

		assertContains(t, "stderr", stderr, "missing sources JAR")
	})

	t.Run("missing_javadoc_is_validation", func(t *testing.T) {
		dir := t.TempDir()
		touchJar(t, dir, "target/app-1.0.0-sources.jar")

		stderr, code := run3(t, dir)
		if code != exitValidation {
			t.Fatalf("exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
		}

		assertContains(t, "stderr", stderr, "missing javadoc JAR")
	})

	// Every module publishes on its own, so every module needs both JARs. The
	// old row let one module supply sources and another javadoc, which would
	// have published moduleA to Maven Central without its javadoc.
	t.Run("each_nested_module_needs_both", func(t *testing.T) {
		dir := t.TempDir()
		touchJar(t, dir, "moduleA/target/a-1.0.0-sources.jar")
		touchJar(t, dir, "moduleA/target/a-1.0.0-javadoc.jar")
		touchJar(t, dir, "moduleB/target/b-1.0.0-sources.jar")
		touchJar(t, dir, "moduleB/target/b-1.0.0-javadoc.jar")

		stderr, code := run3(t, dir)
		if code != 0 {
			t.Fatalf("nested modules each carrying both: exit %d, want 0\nstderr: %s", code, stderr)
		}

		touchJar(t, dir, "moduleC/target/c-1.0.0-sources.jar")

		stderr, code = run3(t, dir)
		if code != exitValidation {
			t.Fatalf("a module missing its javadoc: exit %d, want 1 (EX_VALIDATION)\nstderr: %s", code, stderr)
		}

		assertContains(t, "names the incomplete module", stderr, "moduleC")
		assertContains(t, "names the rule", stderr, "must contain both sources and javadoc JARs")
	})
}

// TestPublishNPMFindTarball_TopLevelOnly covers the non-recursive top-level finder and
// its machine output key.
func TestPublishNPMFindTarball_TopLevelOnly(t *testing.T) {
	t.Parallel()

	t.Run("finds_toplevel_tarball", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "foo-1.0.0.tgz"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		outFile := ghaOutputFile(t)

		_, stderr, code := run(t, runOpts{
			dir: dir,
			env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": outFile},
		}, "publish", "npm", "find-tarball")
		if code != 0 {
			t.Fatalf("find-tarball exit %d\nstderr: %s", code, stderr)
		}

		if got := parseGHAOutputs(t, outFile)["tarball"]; !strings.HasSuffix(got, "foo-1.0.0.tgz") {
			t.Errorf("output tarball=%q, want a path ending foo-1.0.0.tgz", got)
		}
	})

	t.Run("no_tarball_is_no_input", func(t *testing.T) {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()}, "publish", "npm", "find-tarball")
		if code != exitNoInput {
			t.Errorf("no tarball: exit %d, want 66 (EX_NOINPUT)", code)
		}

		assertContains(t, "no tarball", stderr, "no npm tarball file found")
	})

	// The "Only" in this test's name, which the two cases above do not check:
	// a nested tarball must NOT be found. That is the whole distinction from
	// publish google-play find-aab, which searches recursively — and a
	// regression making this finder recursive would leave both cases above
	// green while silently publishing whatever tarball happened to be deepest
	// in the tree.
	t.Run("nested_tarball_is_not_found", func(t *testing.T) {
		dir := t.TempDir()

		nested := filepath.Join(dir, "packages", "inner")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(nested, "inner-1.0.0.tgz"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, stderr, code := run(t, runOpts{dir: dir}, "publish", "npm", "find-tarball")
		if code != exitNoInput {
			t.Errorf("a tarball one directory down was picked up: exit %d, want 66\nstderr: %s", code, stderr)
		}

		assertContains(t, "nested tarball", stderr, "no npm tarball file found")
	})
}

// TestPublishGooglePlayFindAAB_SearchesRecursively covers the RECURSIVE finder variant: an
// .aab nested under the artifact dir must be discovered.
func TestPublishGooglePlayFindAAB_SearchesRecursively(t *testing.T) {
	t.Parallel()

	t.Run("finds_nested_aab", func(t *testing.T) {
		dir := t.TempDir()
		nested := filepath.Join(dir, "artifacts", "sub")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(nested, "app.aab"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		outFile := ghaOutputFile(t)

		_, stderr, code := run(t, runOpts{
			dir: dir,
			env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": outFile},
		}, "publish", "google-play", "find-aab")
		if code != 0 {
			t.Fatalf("find-aab exit %d\nstderr: %s", code, stderr)
		}

		if got := parseGHAOutputs(t, outFile)["aab-file"]; !strings.HasSuffix(got, "app.aab") {
			t.Errorf("output aab-file=%q, want a path ending app.aab", got)
		}
	})

	t.Run("no_aab_is_no_input", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o755); err != nil {
			t.Fatal(err)
		}

		_, stderr, code := run(t, runOpts{dir: dir}, "publish", "google-play", "find-aab")
		if code != exitNoInput {
			t.Errorf("no aab: exit %d, want 66 (EX_NOINPUT)", code)
		}

		assertContains(t, "no aab", stderr, "no AAB file found")
	})
}
