// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// Retention is read-only by default and preserves the release's proof, including
// legacy names, while proposing removal of old binary payloads.
func TestReleaseAssetRetention_KeepsProofByDefault(t *testing.T) {
	t.Parallel()

	type asset struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Size int    `json:"size"`
	}

	assets := func(names ...string) []asset {
		list := make([]asset, 0, len(names))
		for index, name := range names {
			list = append(list, asset{ID: index + 1, Name: name, Size: 10})
		}

		return list
	}
	kept := []string{
		"checksums.sha256", "checksums.sha256.asc", "app-1.0.0-sboms.tar.gz", "app-1.0.0-sboms.tar.gz.asc",
		"app.tar.gz.asc", "app.deb.sig", "slsa-provenance.intoto.json", "slsa-provenance.intoto.json.asc",
		"checksums.txt", "app-0.9.0-sboms.zip",
	}
	deleted := []string{"app.tar.gz", "app.deb", "app-linux-amd64"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("dry run sent %s %s", r.Method, r.URL.Path)
			http.Error(w, "read only", http.StatusMethodNotAllowed)

			return
		}

		var body any

		switch {
		case r.URL.Query().Get("page") != "1":
			body = []any{}
		case strings.HasSuffix(r.URL.Path, "/repos/owner/app/releases"):
			body = []map[string]any{
				{"id": 2, "tag_name": "v2.0.0", "created_at": "2026-02-01T00:00:00Z", "published_at": "2026-02-01T00:00:00Z"},
				{"id": 1, "tag_name": "v1.0.0", "created_at": "2026-01-01T00:00:00Z", "published_at": "2026-01-01T00:00:00Z"},
			}
		case strings.HasSuffix(r.URL.Path, "/releases/2/assets"):
			body = assets("app.tar.gz", "checksums.sha256")
		case strings.HasSuffix(r.URL.Path, "/releases/1/assets"):
			body = assets(slices.Concat(kept, deleted)...)
		default:
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)

	stdout, stderr, code := run(t, runOpts{dir: t.TempDir(), env: map[string]string{
		"FORGE_CI_PROVIDER": "forgejo", "FORGEJO_SERVER_URL": server.URL, "FORGEJO_TOKEN": "synthetic-retention-token",
	}}, "release", "asset-retention", "--repository", "owner/app", "--keep", "1")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	var would []string

	for line := range strings.Lines(stdout + stderr) {
		if _, name, ok := strings.Cut(line, "would delete"); ok {
			fields := strings.Fields(name)
			if len(fields) == 0 {
				t.Fatalf("retention line has no asset name: %q", line)
			}

			would = append(would, fields[0])
		}
	}

	slices.Sort(would)
	slices.Sort(deleted)

	if !slices.Equal(would, deleted) {
		t.Fatalf("dry run would delete %v, want exactly %v\n%s", would, deleted, stdout+stderr)
	}
}
