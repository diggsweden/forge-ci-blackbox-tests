// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// committableUnderForgeCI names the files a fixture may legitimately ship
// inside its .forge-ci/ directory. Everything else there is treated as a
// forge-ci output and rejected.
//
// The allowlist is the inputs rather than the outputs on purpose. Inputs are a
// short, stable set the CLI reads; outputs grow whenever the engine learns to
// write something new, and a guard that enumerates them goes quietly blind the
// moment it falls behind — which is the same failure this guard exists to
// catch. Listing the inputs means an unrecognised file fails loudly and
// someone decides what it is.
func committableUnderForgeCI(rel string) bool {
	switch rel {
	case "artifacts.yml", "artifacts.yaml", "allowed_signers", "allowed_gpg_keys.asc":
		return true
	default:
		return false
	}
}

// TestFixtures_ShipNoGeneratedArtifacts fails when a fixture commits something
// the CLI is supposed to produce.
//
// copyTree prunes the generated build directories named in .gitignore, but
// deliberately preserves .forge-ci inputs. A committed output there arrives
// before the command meant to create it, so an assertion can pass after the
// behaviour it covers has broken. A committed CycloneDX document is enough to
// satisfy an existence check, a JSON parse and a header assertion without the
// generator being installed at all.
//
// .gitignore keeps these paths out of the repository; this guard is what
// notices when a new output path appears that .gitignore does not yet name.
func TestFixtures_ShipNoGeneratedArtifacts(t *testing.T) {
	t.Parallel()

	root := filepath.Join(suiteDir, "fixtures")

	walked := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}

		walked++

		dir, file := filepath.Split(path)

		marker := string(os.PathSeparator) + ".forge-ci" + string(os.PathSeparator)
		if !strings.Contains(dir, marker) {
			return nil
		}

		_, after, _ := strings.Cut(dir, marker)
		rel := filepath.ToSlash(filepath.Join(after, file))

		if committableUnderForgeCI(rel) {
			return nil
		}

		fixtureRel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}

		t.Errorf(
			"%s is not a recognised forge-ci input, so it is treated as an output\n"+
				"    committed as fixture input.\n"+
				"    copyTree places it in the temp project before the CLI runs, so any\n"+
				"    assertion that the CLI produced it passes without the CLI producing it.\n"+
				"    Fix: if the CLI writes it, git rm the file and add its path to\n"+
				"    .gitignore next to the other .forge-ci/ output rules. If it is\n"+
				"    genuinely fixture input the CLI reads, add it to\n"+
				"    committableUnderForgeCI.",
			filepath.ToSlash(fixtureRel),
		)

		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures/: %v", err)
	}

	// No fixture ships a .forge-ci/ file today, which is the healthy state
	// and also what a walk of the wrong directory looks like. The counter is
	// on files seen rather than on matches, so the two stay distinguishable.
	if walked == 0 {
		t.Fatalf("walked no files under %s; this guard would pass whatever the fixtures contain", root)
	}
}

func TestCopyTree_PrunesGeneratedDirectoriesAndKeepsInputs(t *testing.T) {
	t.Parallel()

	src := t.TempDir()

	for _, dir := range []string{"target", "build", ".gradle", "bin", "node_modules", "dist"} {
		path := filepath.Join(src, "module", dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(path, "generated.txt"), []byte("generated"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for rel, body := range map[string]string{
		"module/src/main.txt":     "source",
		".forge-ci/artifacts.yml": "artifacts: []\n",
	} {
		path := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dst := copyTree(t, src)

	for _, dir := range []string{"target", "build", ".gradle", "bin", "node_modules", "dist"} {
		if _, err := os.Stat(filepath.Join(dst, "module", dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("generated directory %q was copied; stat error: %v", dir, err)
		}
	}

	for _, rel := range []string{"module/src/main.txt", ".forge-ci/artifacts.yml"} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Errorf("committed input %q was not copied: %v", rel, err)
		}
	}
}

func TestFixtures_GradleWrapperJarMatchesCommittedChecksum(t *testing.T) {
	t.Parallel()

	wrapperDir := filepath.Join(suiteDir, "fixtures", "gradle-hello", "gradle", "wrapper")
	checksum := strings.Fields(readFile(t, filepath.Join(wrapperDir, "gradle-wrapper.jar.sha256")))
	if len(checksum) != 2 || checksum[1] != "gradle-wrapper.jar" {
		t.Fatalf("invalid gradle-wrapper.jar.sha256: %q", checksum)
	}
	if got := sha256File(t, filepath.Join(wrapperDir, "gradle-wrapper.jar")); got != checksum[0] {
		t.Fatalf("gradle-wrapper.jar SHA-256 = %s, want %s", got, checksum[0])
	}
}

func TestFixtures_ToolchainsArePinned(t *testing.T) {
	t.Parallel()

	pinned := map[string]string{
		"cargo-hello/rust-toolchain.toml":                       `channel = "1.94.0"`,
		"cargo-workspace/rust-toolchain.toml":                   `channel = "1.94.0"`,
		"cargo-hello/Containerfile":                             "rust:1.94.0-slim-bookworm",
		"go-hello/Containerfile":                                "golang:1.27.2-bookworm",
		"gradle-hello/gradle/wrapper/gradle-wrapper.properties": "gradle-9.5.1-bin.zip",
		"gradle-hello/gradle/wrapper/gradle-wrapper.jar.sha256": "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7",
		"android-library/Containerfile":                           "ghcr.io/cirruslabs/android-sdk:35@sha256:c724009e305b4607157287624033ab97f319af44c244bfc9f73b6293f3bb01b9",
		"android-library/gradle/wrapper/gradle-wrapper.properties": "gradle-8.11.1-bin.zip",
	}

	for rel, want := range pinned {
		body := readFile(t, filepath.Join(suiteDir, "fixtures", rel))
		if !strings.Contains(body, want) {
			t.Errorf("%s does not contain pinned input %q", rel, want)
		}
	}

	assertEveryToolchainFileIsListed(t, pinned)
}

// assertEveryToolchainFileIsListed fails when a fixture ships a file of a kind
// this guard pins but which the table above does not name.
//
// The table is complete today, which is exactly why it needs this: a new
// fixture arriving with its own Containerfile would be unpinned and the guard
// would keep reporting green, because it only ever checks the files it already
// knows about. Adding a fixture should fail here until someone pins it.
func assertEveryToolchainFileIsListed(t *testing.T, pinned map[string]string) {
	t.Helper()

	root := filepath.Join(suiteDir, "fixtures")

	kinds := map[string]bool{
		"Containerfile":             true,
		"rust-toolchain.toml":       true,
		"gradle-wrapper.properties": true,
	}

	found := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !kinds[d.Name()] {
			return nil
		}

		found++

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}

		if _, listed := pinned[filepath.ToSlash(rel)]; !listed {
			t.Errorf("fixtures/%s declares a toolchain but is not pinned by this guard; "+
				"add it to the table with the exact version it must carry", filepath.ToSlash(rel))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures/ for toolchain files: %v", err)
	}

	if found == 0 {
		t.Fatalf("found no toolchain files under %s; the completeness check proved nothing", root)
	}
}
