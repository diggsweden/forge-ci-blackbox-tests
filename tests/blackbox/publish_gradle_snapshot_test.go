// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMavenSnapshotTransportRefusesRedirectsAndReplay(t *testing.T) {
	requireTool(t, "mvn")
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			root := t.TempDir()
			publication := filepath.Join(root, "org/example/fixture/pom/1.0.0-SNAPSHOT")
			if err := os.MkdirAll(publication, 0o700); err != nil {
				t.Fatal(err)
			}
			pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example.fixture</groupId><artifactId>pom</artifactId><version>1.0.0-SNAPSHOT</version><packaging>pom</packaging></project>`
			if err := os.WriteFile(filepath.Join(publication, "pom-1.0.0-SNAPSHOT.pom"), []byte(pom), 0o600); err != nil {
				t.Fatal(err)
			}
			var redirected, puts atomic.Int64
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Add(1); w.WriteHeader(http.StatusOK) }))
			defer other.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if status == http.StatusTemporaryRedirect {
					w.Header().Set("Location", other.URL)
					w.WriteHeader(status)

					return
				}
				if request.Method == http.MethodPut {
					puts.Add(1)
					w.WriteHeader(status)

					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			env := map[string]string{"FORGEJO_SERVER_URL": server.URL, "FORGEJO_TOKEN": "synthetic-snapshot-token", "REPOSITORY": "fixture/repo"}
			_, stderr, code := run(t, runOpts{dir: t.TempDir(), env: env}, "--provider", "forgejo", "publish", "forge-packages", "deploy", "--project-type", "gradle", "--snapshot", "--working-dir", root)
			if code == 0 {
				t.Fatal("failed transport reported success")
			}
			if strings.Contains(stderr, "synthetic-snapshot-token") {
				t.Fatal("credential leaked in diagnostics")
			}
			if redirected.Load() != 0 {
				t.Fatal("Maven followed a credential-bearing repository redirect")
			}
			if status == http.StatusServiceUnavailable && puts.Load() != 1 {
				t.Fatalf("failed PUT attempts = %d, want one", puts.Load())
			}
		})
	}
}

func TestGradleSnapshotExportAndRepeatedNativeDeployment(t *testing.T) {
	requireTool(t, "java")
	requireTool(t, "mvn")
	project := copyGradleFixture(t, "gradle-library")
	properties := filepath.Join(project, "gradle.properties")
	body := strings.Replace(readFile(t, properties), "version=2.1.0", "version=2.1.1-SNAPSHOT", 1)
	if err := os.WriteFile(properties, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "publication")
	_, stderr, code := run(t, runOpts{dir: project, env: map[string]string{"JAVA_HOME": detectJavaHome(t)}}, "build", "gradle", "export-publications", "--snapshot", "--output", exported)
	if code != 0 {
		t.Fatalf("export: %d: %s", code, stderr)
	}
	// A publisher accidentally running Maven in the consumer checkout fails.
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte("not a Maven project"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	files := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch request.Method {
		case http.MethodPut:
			if request.Header.Get("Authorization") != "token synthetic-snapshot-token" {
				t.Error("missing scoped registry authentication")
				w.WriteHeader(http.StatusUnauthorized)

				return
			}
			data, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 4<<20))
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)

				return
			}
			files[request.URL.Path] = data
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet, http.MethodHead:
			data, exists := files[request.URL.Path]
			if !exists {
				w.WriteHeader(http.StatusNotFound)

				return
			}
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	env := map[string]string{"FORGEJO_SERVER_URL": server.URL, "FORGEJO_TOKEN": "synthetic-snapshot-token", "REPOSITORY": "fixture/repo"}
	for attempt := 1; attempt <= 2; attempt++ {
		_, stderr, code = run(t, runOpts{dir: project, env: env}, "--provider", "forgejo", "publish", "forge-packages", "deploy", "--project-type", "gradle", "--snapshot", "--working-dir", exported)
		if code != 0 {
			t.Fatalf("snapshot upload %d: %d: %s", attempt, code, stderr)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	base := "/api/packages/fixture/maven/se/digg/test/gradle-library/2.1.1-SNAPSHOT/"
	var metadata struct {
		BuildNumber int `xml:"versioning>snapshot>buildNumber"`
		Versions    []struct {
			Extension  string `xml:"extension"`
			Value      string `xml:"value"`
			Classifier string `xml:"classifier"`
		} `xml:"versioning>snapshotVersions>snapshotVersion"`
	}
	if err := xml.Unmarshal(files[base+"maven-metadata.xml"], &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.BuildNumber != 2 {
		t.Fatalf("repeated snapshot build number = %d", metadata.BuildNumber)
	}
	for _, entry := range metadata.Versions {
		if !strings.HasSuffix(entry.Value, "-2") {
			t.Errorf("metadata did not advance %s: %s", entry.Extension, entry.Value)
		}
		classifier := ""
		if entry.Classifier != "" {
			classifier = "-" + entry.Classifier
		}
		if len(files[base+"gradle-library-"+entry.Value+classifier+"."+entry.Extension]) == 0 {
			t.Errorf("metadata references missing %s/%s bytes", entry.Extension, entry.Classifier)
		}
	}
	if len(metadata.Versions) < 5 {
		t.Fatalf("missing main/POM/module/sources/javadoc: %+v", metadata.Versions)
	}
}
