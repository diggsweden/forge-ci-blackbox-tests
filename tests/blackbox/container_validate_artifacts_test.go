// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for `container validate artifacts` — the
// forge-ci verb on the "package a pre-built artifact into a
// container image" release path (publish-container.yml).
//
// This is the optional container-packaging shape for JVM/NPM projects. Maven
// application JARs can also ship as release assets; when a project additionally
// declares a container, this verb refuses to build it without the expected
// artifact. A false pass here would ship an empty container.
//
// Distinct from the container-FIRST cascade (flow_container_first_test.go),
// which compiles a binary inside the Containerfile and extracts it. Here
// the artifact already exists and the container merely COPYs it — there
// is no binary-extraction step, and the verb's whole job is the
// per-project-type presence check:
//
//	maven, gradle → a top-level *.jar must exist (non-recursive)
//	npm           → any top-level file (unpacked tarball / dist)
//	go, cargo     → any file, searched RECURSIVELY (dist/<os>-<arch>/…)
//
// The recursive-vs-top-level split is the load-bearing behavioural
// difference between the buckets and is asserted directly below. No
// toolchain is required — the verb only stats the filesystem — so this
// runs on a bare runner.

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// mkArtifactDir builds a fresh dir under t.TempDir() containing each
// relative path in files (parent dirs created as needed) and returns its
// absolute path. An empty list yields an existing-but-empty dir.
func mkArtifactDir(t *testing.T, files ...string) string {
	t.Helper()

	dir := t.TempDir()

	for _, rel := range files {
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// TestContainerValidateArtifacts_Buckets exercises the three matcher
// buckets and — the point of the test — the recursive-vs-top-level
// distinction between them. A jar buried in a subdir must NOT satisfy
// maven/gradle (non-recursive), while a binary buried under
// dist/<os>-<arch>/ MUST satisfy go/cargo (recursive).
func TestContainerValidateArtifacts_Buckets(t *testing.T) {
	t.Parallel()

	const exOK = 0 // artifacts present

	cases := []struct {
		name        string
		projectType string
		files       []string
		wantExit    int
		wantErr     string
	}{
		// maven/gradle: top-level *.jar only.
		{"maven_toplevel_jar_ok", "maven", []string{"app-1.0.0.jar"}, exOK, ""},
		{"maven_jar_in_subdir_ignored", "maven", []string{"classes/app-1.0.0.jar"}, exitValidation, "no Maven artifacts in"},
		{"maven_only_nonjar_rejected", "maven", []string{"app-1.0.0.txt"}, exitValidation, "no Maven artifacts in"},
		{"maven_empty_rejected", "maven", nil, exitValidation, "no Maven artifacts in"},
		{"gradle_toplevel_jar_ok", "gradle", []string{"libs-app.jar"}, exOK, ""},
		{"gradle_jar_in_subdir_ignored", "gradle", []string{"libs/app.jar"}, exitValidation, "no Gradle artifacts in"},

		// npm: any top-level file (the unpacked tarball / dist tree).
		{"npm_any_toplevel_file_ok", "npm", []string{"package.tgz"}, exOK, ""},
		{"npm_dist_file_toplevel_ok", "npm", []string{"index.js"}, exOK, ""},
		{"npm_empty_rejected", "npm", nil, exitValidation, "no NPM artifacts in"},

		// go/cargo: any file, RECURSIVELY — binaries land at
		// dist/<goos>-<goarch>/<name>-<goos>-<goarch>.
		{"go_nested_binary_ok", "go", []string{"linux-amd64/tool-linux-amd64"}, exOK, ""},
		{"cargo_nested_binary_ok", "cargo", []string{"linux-amd64/tool-linux-amd64"}, exOK, ""},
		{"go_empty_rejected", "go", nil, exitValidation, "no Go artifacts in"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := mkArtifactDir(t, tc.files...)

			_, stderr, code := run(t, runOpts{dir: t.TempDir()},
				"container", "validate", "artifacts",
				"--project-type", tc.projectType,
				"--artifact-dir", dir)

			if code != tc.wantExit {
				t.Fatalf("%s: exit %d, want %d\nstderr: %s", tc.name, code, tc.wantExit, stderr)
			}

			// Exit 1 has other causes too; the message names this rule.
			if tc.wantErr != "" {
				assertContains(t, tc.name, stderr, tc.wantErr)
			}
		})
	}
}

// TestContainerValidateArtifacts_UnknownTypeIsUsageError pins the
// public exit-code contract: an unrecognised project type is a caller
// mistake (EX_USAGE=2), not a validation failure of the inputs.
func TestContainerValidateArtifacts_UnknownTypeIsUsageError(t *testing.T) {
	t.Parallel()

	dir := mkArtifactDir(t, "whatever.jar")

	_, stderr, code := run(t, runOpts{dir: t.TempDir()},
		"container", "validate", "artifacts",
		"--project-type", "rust-but-spelled-wrong",
		"--artifact-dir", dir)

	if code != exitUsage {
		t.Fatalf("unknown project type: exit %d, want 2 (EX_USAGE)\nstderr: %s", code, stderr)
	}

	assertContains(t, "unknown project type", stderr, "unknown project type: rust-but-spelled-wrong")
}

// TestContainerValidateArtifacts_MissingDirIsNoInput confirms a non-existent
// artifact dir is a missing input (EX_NOINPUT), not a crash and not "no
// artifacts": the upstream build stage handed over nothing at all, which is
// the same class every other absent input in the CLI reports, and the message
// names the directory so the operator can see which hand-off is missing.
func TestContainerValidateArtifacts_MissingDirIsNoInput(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, stderr, code := run(t, runOpts{dir: t.TempDir()},
		"container", "validate", "artifacts",
		"--project-type", "maven",
		"--artifact-dir", missing)

	if code != exitNoInput {
		t.Fatalf("missing dir: exit %d, want 66 (EX_NOINPUT)\nstderr: %s", code, stderr)
	}

	assertContains(t, "names the directory", stderr, "does-not-exist")
	assertContains(t, "names the class", stderr, "missing input")
}

// TestContainerValidateArtifacts_AllEmptyArtifactsAreRefused closes the gap the
// file header names: "a false pass here would ship an empty container".
//
// A zero-byte jar or binary satisfies "a matching file is present" while being
// exactly the empty artifact this verb exists to catch — a truncated upload, or
// a build stage that produced a stub. Verified by probe before the check
// existed: a 0-byte app.jar exited 0, with the verb printing the size as 0 on
// the success line.
//
// The rule is "at least one matched artifact has content", not "none is empty":
// a real artifact beside an incidental empty file is a normal build output, and
// refusing that would be a new false failure.
func TestContainerValidateArtifacts_AllEmptyArtifactsAreRefused(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		projectType string
		files       []string
		empty       []string
		wantExit    int
	}{
		{"maven_only_an_empty_jar", "maven", nil, []string{"app-1.0.0.jar"}, exitValidation},
		{"go_only_an_empty_binary", "go", nil, []string{"linux-amd64/tool-linux-amd64"}, exitValidation},
		{"npm_only_an_empty_file", "npm", nil, []string{"index.js"}, exitValidation},
		{"maven_one_real_jar_beside_an_empty_one", "maven", []string{"app-1.0.0.jar"}, []string{"sources.jar"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := mkArtifactDir(t, tc.files...)

			for _, rel := range tc.empty {
				abs := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(abs, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			_, stderr, code := run(t, runOpts{dir: t.TempDir()},
				"container", "validate", "artifacts",
				"--project-type", tc.projectType,
				"--artifact-dir", dir)

			if code != tc.wantExit {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, tc.wantExit, stderr)
			}

			if tc.wantExit == exitValidation {
				// Distinct from the no-matches refusal: "nothing was uploaded"
				// and "what was uploaded is empty" send the operator elsewhere.
				assertContains(t, tc.name, stderr, "are empty (0 bytes)")
			}
		})
	}
}
