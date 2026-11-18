// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// TestFixtures_ToolchainsArePinned checks the properties that make a
// fixture's toolchain inputs pinned, over every such file the fixtures ship,
// so a new fixture is covered without editing this test:
//
//   - every Containerfile base names an explicit tag or digest, never an
//     implicit or explicit `latest`;
//   - a Go or Rust builder image and every rust-toolchain.toml use the version
//     .mise.toml pins, so the fixtures build with the toolchain the suite runs;
//   - every Gradle wrapper names an exact distribution version and the
//     distribution's SHA-256, so the wrapper verifies what it downloads.
//
// TestFixtures_GradleWrapperJarMatchesCommittedChecksum covers the wrapper jar.
func TestFixtures_ToolchainsArePinned(t *testing.T) {
	t.Parallel()

	mise := readFile(t, filepath.Join(suiteDir, ".mise.toml"))
	want := map[string]string{
		"golang": miseVersion(t, mise, `(?m)^go = "([^"]+)"`),
		"rust":   miseVersion(t, mise, `(?m)^rust = \{ version = "([^"]+)"`),
	}

	root := filepath.Join(suiteDir, "fixtures")
	found := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}

		rel = filepath.ToSlash(rel)

		switch d.Name() {
		case "Containerfile":
			found++

			assertContainerfileBasesPinned(t, rel, readFile(t, path), want)
		case "rust-toolchain.toml":
			found++

			if !strings.Contains(readFile(t, path), `channel = "`+want["rust"]+`"`) {
				t.Errorf("%s: channel is not the .mise.toml rust %s", rel, want["rust"])
			}
		case "gradle-wrapper.properties":
			found++

			properties := readFile(t, path)
			if !gradleDistributionRE.MatchString(properties) {
				t.Errorf("%s: distributionUrl does not name an exact gradle-X.Y[.Z] distribution", rel)
			}
			if !gradleDistributionSumRE.MatchString(properties) {
				t.Errorf("%s: distributionSha256Sum is not a SHA-256", rel)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures/ for toolchain files: %v", err)
	}

	if found == 0 {
		t.Fatalf("found no toolchain files under %s; this guard proved nothing", root)
	}
}

// assertContainerfileBasesPinned checks every FROM of one Containerfile. A
// base that is `scratch` or an earlier stage is not an image reference.
func assertContainerfileBasesPinned(t *testing.T, rel, body string, toolchain map[string]string) {
	t.Helper()

	stages := map[string]bool{"scratch": true}

	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}

		fields = slices.DeleteFunc(fields[1:], func(f string) bool { return strings.HasPrefix(f, "--") })
		if len(fields) == 0 {
			t.Errorf("%s: %q names no base", rel, line)

			continue
		}

		if len(fields) == 3 && strings.EqualFold(fields[1], "AS") {
			stages[fields[2]] = true
		}

		if image := fields[0]; !stages[image] {
			assertImagePinned(t, rel, image, toolchain)
		}
	}
}

func assertImagePinned(t *testing.T, rel, image string, toolchain map[string]string) {
	t.Helper()

	name, digest, _ := strings.Cut(image, "@")
	repo, tag := name, ""

	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		repo, tag = name[:i], name[i+1:]
	}

	if digest == "" && (tag == "" || tag == "latest") {
		t.Errorf("%s: base %q names no explicit tag or digest", rel, image)
	}

	if version, ok := toolchain[repo[strings.LastIndex(repo, "/")+1:]]; ok && !strings.HasPrefix(tag, version+"-") {
		t.Errorf("%s: builder %q is not the .mise.toml version %s", rel, image, version)
	}
}

// miseVersion returns the first submatch of pattern in .mise.toml.
func miseVersion(t *testing.T, mise, pattern string) string {
	t.Helper()

	m := regexp.MustCompile(pattern).FindStringSubmatch(mise)
	if m == nil {
		t.Fatalf(".mise.toml has no version matching %s", pattern)
	}

	return m[1]
}

//nolint:gochecknoglobals // read-only compiled pattern.
var gradleDistributionRE = regexp.MustCompile(`(?m)^distributionUrl=\S*/gradle-\d+\.\d+(\.\d+)?-bin\.zip$`)

//nolint:gochecknoglobals // read-only compiled pattern.
var gradleDistributionSumRE = regexp.MustCompile(`(?m)^distributionSha256Sum=[0-9a-f]{64}$`)
