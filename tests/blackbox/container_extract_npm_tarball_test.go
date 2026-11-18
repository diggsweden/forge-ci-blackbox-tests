// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Container packaging needs the package that arrived, not a prescribed
// dist/cli.js layout. Extraction strips package/ and consumes the archive;
// missing, nested-only and corrupt archives must not pass the image job.
func TestContainerExtractNPMTarball_PackageHandoff(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, archive string
		corrupt       bool
		want          int
	}{
		{name: "tgz", archive: "demo.tgz"},
		{name: "tar_gz", archive: "demo.tar.gz"},
		{name: "missing", want: exitNoInput},
		{name: "nested_only", archive: "nested/demo.tgz", want: exitNoInput},
		{name: "corrupt", archive: "demo.tgz", corrupt: true, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if tc.archive != "" {
				body := npmPackageArchive(t)
				if tc.corrupt {
					body = []byte("not an archive")
				}
				path := filepath.Join(dir, tc.archive)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			_, stderr, code := run(t, runOpts{dir: dir}, "container", "extract-npm-tarball")
			if (tc.want >= 0 && code != tc.want) || (tc.want < 0 && code == 0) {
				t.Fatalf("extract-npm-tarball exit %d, want %d: %s", code, tc.want, stderr)
			}
			if tc.want != 0 {
				if tc.archive != "" && !fileExists(filepath.Join(dir, tc.archive)) {
					t.Error("a refused archive must remain available for diagnosis")
				}

				return
			}

			if got := readFile(t, filepath.Join(dir, "lib", "index.js")); got != "export default 42;\n" {
				t.Errorf("extracted package contents = %q", got)
			}
			if fileExists(filepath.Join(dir, tc.archive)) || fileExists(filepath.Join(dir, "package")) {
				t.Error("extraction must consume the archive and strip the package prefix")
			}
		})
	}
}

func npmPackageArchive(t *testing.T) []byte {
	t.Helper()

	var body bytes.Buffer
	zipped := gzip.NewWriter(&body)
	archive := tar.NewWriter(zipped)
	const contents = "export default 42;\n"
	if err := archive.WriteHeader(&tar.Header{Name: "package/lib/index.js", Mode: 0o644, Size: int64(len(contents))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(archive.Close(), zipped.Close()); err != nil {
		t.Fatal(err)
	}

	return body.Bytes()
}
