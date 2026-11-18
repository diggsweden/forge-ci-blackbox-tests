// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestContainerBuild_SourceDateEpochPinsTheDigest builds one native image three
// times with `forge-ci container build --mode oci --source-date-epoch`, each
// into a fresh OCI layout, and compares the exported manifest digests: the same
// epoch must give the same digest, and a different epoch a different one. The
// second half is the control: without it, equal digests are also what a build
// that ignored the epoch, or never ran, would produce.
func TestContainerBuild_SourceDateEpochPinsTheDigest(t *testing.T) {
	requireTool(t, "buildah")

	proj := t.TempDir()
	for name, body := range map[string]string{
		"Containerfile": "FROM scratch\nCOPY payload /payload\n",
		"payload":       "reproducible-payload\n",
	} {
		if err := os.WriteFile(filepath.Join(proj, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	env := map[string]string{"CONTAINERS_STORAGE_CONF": buildahStorageConf(t)}

	build := func(epoch string) string {
		layout := filepath.Join(t.TempDir(), "layout")
		if _, stderr, code := run(t, runOpts{dir: proj, env: env}, "container", "build",
			"--mode", "oci", "--defer-scan", "--output-dir", layout,
			"--file", "Containerfile", "--platform", "linux/"+runtime.GOARCH,
			"--source-date-epoch", epoch); code != 0 {
			t.Fatalf("container build (epoch %s) exit %d\nstderr: %s", epoch, code, stderr)
		}

		return ociManifestDigest(t, layout)
	}

	first, second := build("1700000000"), build("1700000000")
	if first != second {
		t.Errorf("the same --source-date-epoch gave different digests:\n  first:  %s\n  second: %s", first, second)
	}

	if shifted := build("1800000000"); shifted == first {
		t.Errorf("a different --source-date-epoch gave the same digest %s; the epoch does not reach the image", first)
	}
}

// ociManifestDigest returns the digest of the one manifest in the OCI layout,
// after checking that the manifest, its config and every layer blob hash to
// the digests they are stored under.
func ociManifestDigest(t *testing.T, layout string) string {
	t.Helper()

	type descriptor struct {
		Digest string `json:"digest"`
	}

	readBlob := func(d descriptor) []byte {
		t.Helper()

		digest, ok := strings.CutPrefix(d.Digest, "sha256:")
		if !ok || len(digest) != 64 {
			t.Fatalf("unexpected OCI digest %q", d.Digest)
		}

		path := filepath.Join(layout, "blobs", "sha256", digest)
		if actual := sha256File(t, path); actual != digest {
			t.Fatalf("OCI blob %s hashes to %s", digest, actual)
		}

		return []byte(readFile(t, path))
	}

	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	decodeJSON(t, "index.json", readFile(t, filepath.Join(layout, "index.json")), &index)

	if len(index.Manifests) != 1 {
		t.Fatalf("want one OCI manifest, got %d", len(index.Manifests))
	}

	var manifest struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}
	if err := json.Unmarshal(readBlob(index.Manifests[0]), &manifest); err != nil {
		t.Fatal(err)
	}

	readBlob(manifest.Config)

	if len(manifest.Layers) == 0 {
		t.Fatal("want the COPY payload layer, got none")
	}

	for _, layer := range manifest.Layers {
		readBlob(layer)
	}

	return index.Manifests[0].Digest
}
