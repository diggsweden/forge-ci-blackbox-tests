// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestNPMPublish_VersionSpecificTag exercises real npm against a local registry
// observer: the PUT's actual dist-tags, rather than the CLI's success text, are
// the publication evidence. The registry is disposable and never public.
func TestNPMPublish_VersionSpecificTag(t *testing.T) {
	for _, tc := range []struct{ version, tag string }{
		{"0.1.0", "release-0.1.0"},
		{"0.2.0-rc.1", "release-0.2.0-rc.1"},
		{"0.3.0+build.7", "release-0.3.0"},
	} {
		t.Run(tc.version, func(t *testing.T) { testNPMPublishVersion(t, tc.version, tc.tag) })
	}
}

func testNPMPublishVersion(t *testing.T, version, tag string) {
	t.Helper()
	requireTool(t, "npm")
	proj := copyTree(t, fixture("npm-lib"))
	manifest := filepath.Join(proj, "package.json")
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var pkg map[string]any
	if decodeErr := json.Unmarshal(body, &pkg); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	pkg["version"] = version
	// Publishing an already-built archive must not execute consumer code with
	// registry credentials. A real lifecycle invocation would fail the publish.
	pkg["scripts"] = map[string]string{"prepublishOnly": "node -e 'process.exit(91)'", "publish": "node -e 'process.exit(92)'"}
	body, err = json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runTool(t, proj, "npm", "pack", "--ignore-scripts"); code != 0 {
		t.Fatalf("npm pack: %d: %s", code, stderr)
	}
	var mu sync.Mutex
	var published map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":"not found"}`)

			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}
		var body struct {
			Tags map[string]string `json:"dist-tags"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			t.Errorf("publication body: %v", err)
			w.WriteHeader(http.StatusBadRequest)

			return
		}
		mu.Lock()
		published = body.Tags
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{"NODE_AUTH_TOKEN": "synthetic-registry-token"}}, "publish", "npm", "deploy", "--registry", server.URL, "--npm-tag", "release-{version}")
	if code != 0 {
		t.Fatalf("publish: %d: %s", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	canonical, _, _ := strings.Cut(version, "+")
	if len(published) != 1 || published[tag] != canonical {
		t.Fatalf("published dist-tags = %v", published)
	}
	if canonical != version && !strings.Contains(stderr, "npm removes build metadata") {
		t.Fatal("metadata normalization was not announced")
	}
}
