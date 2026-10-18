// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestModernCentralPluginRoutesSnapshotsWithoutReleaseAuthorization(t *testing.T) {
	requireTool(t, "mvn")
	var mu sync.Mutex
	var requests atomic.Int64
	files := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(request.URL.Path, "/snapshots/") {
			t.Errorf("snapshot reached release API: %s", request.URL.Path)
			w.WriteHeader(http.StatusForbidden)

			return
		}
		switch request.Method {
		case http.MethodPut:
			username, password, ok := request.BasicAuth()
			if !ok || username != "fixture" || password != "synthetic-central-token" {
				w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}
			data, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1<<20))
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)

				return
			}
			files[request.URL.Path] = data
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if body, exists := files[request.URL.Path]; exists {
				_, _ = w.Write(body)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	project := copyTree(t, fixture("maven-central-snapshot"))
	settings := filepath.Join(project, "settings.xml")
	// This row supplies its own settings. Maven takes the first --settings,
	// so the harness's default MAVEN_ARGS settings must not shadow this file.
	env := map[string]string{"MAVEN_CENTRAL_USERNAME": "fixture", "MAVEN_CENTRAL_PASSWORD": "synthetic-central-token", "MAVEN_ARGS": "-Dmaven.repo.local=" + filepath.Join(isolatedHome(), ".m2", "repository")}
	args := []string{"publish", "maven-central", "deploy", "--snapshot", "--profile", "publish", "--settings-path", settings, "--cli-opts", "-Dfixture.registry=" + server.URL}
	_, stderr, code := run(t, runOpts{dir: project, env: env}, append(append([]string{}, args...), "--validate-only")...)
	if code != 0 || requests.Load() != 0 {
		t.Fatalf("reactor preflight contacted the publisher or failed: requests=%d exit=%d: %s", requests.Load(), code, stderr)
	}
	_, stderr, code = run(t, runOpts{dir: project, env: env}, args...)
	if code != 0 {
		t.Fatalf("modern plugin snapshot: %d: %s", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	var poms int
	for name, data := range files {
		if strings.HasSuffix(name, ".pom") {
			poms++
			if !strings.Contains(string(data), "1.2.3-SNAPSHOT") {
				t.Error("uploaded POM lost snapshot identity")
			}
		}
	}
	if poms != 1 {
		t.Fatalf("uploaded snapshot POM count = %d", poms)
	}
}

func TestMavenSnapshotRefusesStableReactorBeforeUpload(t *testing.T) {
	requireTool(t, "mvn")
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	project := copyTree(t, fixture("maven-snapshot-guard"))
	_, stderr, code := run(t, runOpts{dir: project}, "publish", "maven-central", "deploy", "--snapshot", "--profile", "publish", "--cli-opts", "-Dfixture.registry="+server.URL)
	if code == 0 || !strings.Contains(stderr, "snapshot publication requires a -SNAPSHOT version") {
		t.Fatalf("snapshot gate: %d: %s", code, stderr)
	}
	if requests.Load() != 0 {
		t.Fatalf("stable version reached registry before refusal: %d requests", requests.Load())
	}
}

func TestMavenSnapshotRechecksCredentialActivatedProfiles(t *testing.T) {
	requireTool(t, "mvn")
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	project := copyTree(t, fixture("maven-environment-profile"))
	opts := runOpts{dir: project, env: map[string]string{"MAVEN_CENTRAL_PASSWORD": "synthetic-profile-token"}}
	args := []string{"publish", "maven-central", "deploy", "--snapshot", "--profile", "publish", "--cli-opts", "-Dfixture.registry=" + server.URL}
	_, stderr, code := run(t, opts, append(append([]string{}, args...), "--validate-only")...)
	if code != 0 {
		t.Fatalf("secret-free preflight: %d: %s", code, stderr)
	}
	_, stderr, code = run(t, opts, args...)
	if code == 0 || !strings.Contains(stderr, "snapshot publication requires a -SNAPSHOT version") {
		t.Fatalf("credential-activated stable model was not refused: %d: %s", code, stderr)
	}
	if requests.Load() != 0 {
		t.Fatalf("version drift contacted registry: %d requests", requests.Load())
	}
}
