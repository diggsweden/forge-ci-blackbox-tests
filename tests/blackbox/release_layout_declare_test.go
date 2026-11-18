// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func declaredDist(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"app.tar.gz":    "archive\n",
		"app.spdx.json": `{"spdxVersion":"SPDX-2.3","name":"spdx"}`,
		"app.cdx.json":  `{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:cdx"}`,
	} {
		if err := os.WriteFile(filepath.Join(root, "dist", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func TestReleaseFilesDeclare_RefusesAnSBOMItCannotBundle(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args     []string
		wantExit int
		wantErr  string
	}{
		"missing version": {[]string{"--project-name", "widget"}, exitUsage, "pass --project-name and --version"},
		"missing project": {[]string{"--version", "1.2.3"}, exitUsage, "pass --project-name and --version"},
		"asset overlap":   {[]string{"--project-name", "widget", "--version", "1.2.3", "--asset", "dist/app.spdx.json"}, exitValidation, "--sbom file is also an --asset: dist/app.spdx.json"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := declaredDist(t)
			args := append([]string{"release", "files", "declare", "--asset", "dist/app.tar.gz", "--sbom", "dist/app.spdx.json"}, tc.args...)
			_, stderr, code := run(t, runOpts{dir: root}, args...)
			if code != tc.wantExit {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, tc.wantExit, stderr)
			}

			assertContains(t, "refusal", stderr, tc.wantErr)

			for _, name := range []string{"release-files.json", "checksums.sha256", "widget-1.2.3-sboms.tar.gz"} {
				if fileExists(filepath.Join(root, "dist", name)) {
					t.Errorf("refused declaration wrote dist/%s", name)
				}
			}
		})
	}
}

func TestReleaseFilesDeclare_WritesTheOneReleaseLayout(t *testing.T) {
	t.Parallel()

	key := bootstrapGPGKey(t)
	root := declaredDist(t)
	dist := filepath.Join(root, "dist")
	const bundle = "widget-1.2.3-sboms.tar.gz"

	if _, stderr, code := run(t, runOpts{dir: root},
		"release", "files", "declare", "--asset", "dist/app.tar.gz", "--sbom", "dist/*.json",
		"--repository", "owner/widget", "--version", "v1.2.3"); code != 0 {
		t.Fatalf("declare exit %d\nstderr: %s", code, stderr)
	}

	listed := checksumManifestNames(t, filepath.Join(dist, "checksums.sha256"))
	slices.Sort(listed)

	if want := []string{"app.tar.gz", bundle}; !slices.Equal(listed, want) {
		t.Fatalf("checksums list %v, want %v", listed, want)
	}

	entries, count := readTarGz(t, filepath.Join(dist, bundle))
	if count != 2 || len(entries) != 2 {
		t.Fatalf("bundle contains %d entries: %v", count, entries)
	}

	for _, name := range []string{"app.spdx.json", "app.cdx.json"} {
		if entries[name] != readFile(t, filepath.Join(dist, name)) {
			t.Errorf("bundle changed %s", name)
		}
	}

	var manifest struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	decodeJSON(t, "release manifest", readFile(t, filepath.Join(dist, "release-files.json")), &manifest)
	names := make([]string, 0, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		names = append(names, asset.Name)
	}

	slices.Sort(names)

	if want := []string{"app.tar.gz", "checksums.sha256", bundle}; !slices.Equal(names, want) {
		t.Fatalf("manifest lists %v, want %v", names, want)
	}

	const statement = "slsa-provenance.intoto.json"
	if _, stderr, code := run(t, runOpts{dir: root, env: provenanceEnv},
		"release", "provenance", "--checksums-from-manifest", "--manifest", "dist/release-files.json", "--dist-dir", "dist",
		"--started-on", provStartedOn, "--go-sum", "", "--output", "dist/"+statement); code != 0 {
		t.Fatalf("provenance exit %d\nstderr: %s", code, stderr)
	}

	var stmt provStatement
	decodeJSON(t, "statement", readFile(t, filepath.Join(dist, statement)), &stmt)
	subjects := make([]string, 0, len(stmt.Subject))
	for _, subject := range stmt.Subject {
		subjects = append(subjects, subject.Name)
	}

	slices.Sort(subjects)

	if !slices.Equal(subjects, listed) {
		t.Fatalf("provenance subjects %v differ from checksums %v", subjects, listed)
	}

	if fileExists(filepath.Join(dist, statement+".bundle")) {
		t.Fatal("provenance writer signed its own statement")
	}

	if _, stderr, code := run(t, runOpts{dir: root, env: key.signingEnv(t)},
		"release", "sign", "--method", "gpg", "--checksums-from-manifest", "--files-from-manifest",
		"--file", "dist/"+statement, "--manifest", "dist/release-files.json", "--dist-dir", "dist"); code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	for _, name := range []string{"checksums.sha256", "app.tar.gz", bundle, statement} {
		file := filepath.Join(dist, name)
		cmd := toolCommand(t, root, map[string]string{"GNUPGHOME": key.gnupgHome}, "gpg", "--verify", file+".asc", file)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("signature %s: %v\n%s", name, err, out)
		}
	}

	for _, name := range []string{"app.spdx.json.asc", "app.cdx.json.asc", "checksums.txt"} {
		if fileExists(filepath.Join(dist, name)) {
			t.Errorf("unexpected release file %s", name)
		}
	}

	unsigned := t.TempDir()
	if err := os.CopyFS(unsigned, os.DirFS(root)); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(unsigned, "dist", "app.tar.gz.asc")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		dir      string
		wantExit int
	}{{unsigned, exitValidation}, {root, 0}} {
		if err := os.WriteFile(filepath.Join(tc.dir, "notes.md"), []byte("notes\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, stderr, code := run(t, runOpts{dir: tc.dir}, "release", "files", "manifest", "--manifest", "dist/release-files.json", "--dist-dir", "dist"); code != 0 {
			t.Fatalf("manifest exit %d\nstderr: %s", code, stderr)
		}

		_, stderr, code := run(t, runOpts{dir: tc.dir}, "--provider", "forgejo", "release", "publish", "--dry-run", "--tag", "v1.2.3", "--repository", "owner/widget", "--release-notes-file", "notes.md")
		if code != tc.wantExit {
			t.Fatalf("publish exit %d, want %d\nstderr: %s", code, tc.wantExit, stderr)
		}

		if tc.wantExit != 0 {
			assertContains(t, "unsigned-file refusal", stderr, "declares dist/app.tar.gz without its signature")
		}
	}
}
