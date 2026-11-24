// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

type privateInputRegistry struct {
	server *httptest.Server
	repo   string
	reads  atomic.Int32
	writes atomic.Int32
	denied atomic.Bool
}

func newPrivateInputRegistry(t *testing.T) *privateInputRegistry {
	t.Helper()
	fixture := &privateInputRegistry{}
	store := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		user, password, _ := request.BasicAuth()
		if user != "selected" || password != "fixture" {
			response.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			response.WriteHeader(http.StatusUnauthorized)

			return
		}
		if fixture.denied.Load() {
			response.WriteHeader(http.StatusForbidden)

			return
		}
		if request.Method == http.MethodGet || request.Method == http.MethodHead {
			fixture.reads.Add(1)
		} else {
			fixture.writes.Add(1)
		}
		store.ServeHTTP(response, request)
	}))
	t.Cleanup(fixture.server.Close)
	fixture.repo = strings.TrimPrefix(fixture.server.URL, "http://") + "/owner/base"

	return fixture
}

func (fixture *privateInputRegistry) authFile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	body := fmt.Sprintf(`{"auths":{%q:{"username":"selected","password":%q}}}`, strings.Split(fixture.repo, "/")[0], password)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func (fixture *privateInputRegistry) seed(t *testing.T, tag, revision string) string {
	t.Helper()
	image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		OS: "linux", Architecture: runtime.GOARCH,
		Config: v1.Config{Labels: map[string]string{"org.opencontainers.image.revision": revision, "org.example.input": "reviewed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = crane.Push(image, fixture.repo+":"+tag, crane.WithContext(t.Context()), crane.Insecure,
		crane.WithAuth(&authn.Basic{Username: "selected", Password: "fixture"})); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}

	return fixture.repo + "@" + digest.String()
}

func preparedBuildJSON(t *testing.T, fixture *privateInputRegistry, parent string, cache bool) string {
	t.Helper()
	build := map[string]any{
		"name": "base", "arch": runtime.GOARCH, "platform": "linux/" + runtime.GOARCH,
		"container-file": "Containerfile", "context": ".", "image-repository": fixture.repo,
		"candidate-tag": "staging-v1.2.3", "final-tag-name": "v1.2.3",
		"build-args": "BASE_IMAGE=" + parent, "registry-inputs": map[string]string{"BASE_IMAGE": parent},
	}
	if cache {
		build["cache-tag"] = "cache"
		build["required-labels"] = "org.example.input=reviewed"
	}
	body, err := json.Marshal(build)
	if err != nil {
		t.Fatal(err)
	}

	return string(body)
}

func preparedInputArgs(build, command string) []string {
	return []string{"container", "release-images", command, "--build-json", build,
		"--release-sha", strings.Repeat("a", 40), "--server-url", "https://forge.example",
		"--repository", "owner/app", "--inputs-dir", "inputs"}
}

// Fetch real authenticated OCI bytes, then close the registry. A warm prepared
// build must succeed without credentials, source files or a builder invocation.
// Corrupt bindings must fail before staging output, never fall back to a build.
func TestPreparedInputs_WarmOfflineReuseAndTamperRefusal(t *testing.T) {
	fixture := newPrivateInputRegistry(t)
	parent := fixture.seed(t, "cache", strings.Repeat("a", 40))
	auth := fixture.authFile(t, "fixture")
	build := preparedBuildJSON(t, fixture, parent, true)
	root := t.TempDir()
	if _, stderr, code := run(t, runOpts{dir: root}, append(preparedInputArgs(build, "fetch-inputs"), "--auth-file", auth)...); code != 0 {
		t.Fatalf("fetch: exit=%d %s", code, stderr)
	}
	writes := fixture.writes.Load()
	fixture.server.Close()
	args := append(preparedInputArgs(build, "build-prepared"), "--release-tag", "v1.2.3", "--created", "2026-11-06T00:00:00Z", "--metadata-dir", "staged")
	for _, mode := range []string{"verified", "source", "platform", "parent", "manifest", "blob"} {
		t.Run(mode, func(t *testing.T) {
			dir := copyTree(t, root)
			switch mode {
			case "source", "platform", "parent":
				path := filepath.Join(dir, "inputs", "inputs.json")
				var record map[string]any
				if err := json.Unmarshal([]byte(readFile(t, path)), &record); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "source":
					record["sourceSHA"] = strings.Repeat("b", 40)
				case "platform":
					record["arch"] = "foreign"
				case "parent":
					record["parents"] = map[string]string{"BASE_IMAGE": fixture.repo + "@sha256:" + strings.Repeat("b", 64)}
				}
				body, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(dir, "inputs", "BASE_IMAGE", "forge-ci-source-manifest.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "blob":
				paths, err := filepath.Glob(filepath.Join(dir, "inputs", "BASE_IMAGE", "blobs", "sha256", "*"))
				if err != nil || len(paths) == 0 {
					t.Fatal("missing OCI blobs", err)
				}
				if err = os.WriteFile(paths[0], []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, stderr, code := run(t, runOpts{dir: dir}, args...)
			metadata := filepath.Join(dir, "staged", "base-arch-"+runtime.GOARCH, "base-"+runtime.GOARCH+".json")
			if mode == "verified" {
				if code != 0 || !fileExists(metadata) {
					t.Fatalf("offline reuse: exit=%d %s", code, stderr)
				}
			} else if code != exitValidation || fileExists(metadata) {
				t.Fatalf("accepted tampered %s: exit=%d %s", mode, code, stderr)
			}
		})
	}
	if fixture.writes.Load() != writes {
		t.Fatal("prepared build mutated the registry")
	}
}

// The cache-only CLI must use selected credentials and never rescue a refusal
// with valid ambient credentials. A missing or mismatched cache cannot build.
func TestArchitectureCache_ExplicitAuthAndNoFallback(t *testing.T) {
	fixture := newPrivateInputRegistry(t)
	fixture.seed(t, "cache", strings.Repeat("a", 40))
	valid := fixture.authFile(t, "fixture")
	invalid := fixture.authFile(t, "wrong")
	amb := filepath.Dir(valid)
	if err := os.WriteFile(filepath.Join(amb, "config.json"), []byte(readFile(t, valid)), 0o600); err != nil {
		t.Fatal(err)
	}
	writes := fixture.writes.Load()
	for _, mode := range []string{"verified", "bad-auth", "missing-auth", "absent", "wrong-label", "denied"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			auth, tag := valid, "cache"
			switch mode {
			case "bad-auth":
				auth = invalid
			case "missing-auth":
				auth = filepath.Join(dir, "missing.json")
			case "absent":
				tag = "absent"
			}
			fixture.denied.Store(mode == "denied")
			args := []string{"container", "multiarch-image", "build-arch", "--stage", "--cache-only",
				"--arch", runtime.GOARCH, "--source-sha", strings.Repeat("a", 40), "--server-url", "https://forge.example",
				"--repository", "owner/app", "--image-repository", fixture.repo, "--name", "base",
				"--cache-tag", tag, "--require-label", "org.example.input=reviewed", "--auth-file", auth, "--metadata-dir", "metadata"}
			if mode == "wrong-label" {
				args = append(args, "--require-label", "org.example.absent=required")
			}
			_, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{"DOCKER_CONFIG": amb, "REGISTRY_AUTH_FILE": valid}}, args...)
			metadata := filepath.Join(dir, "metadata", "base-"+runtime.GOARCH+".json")
			if mode == "verified" {
				if code != 0 || !fileExists(metadata) {
					t.Fatalf("cache hit: exit=%d %s", code, stderr)
				}
			} else {
				want := exitNoInput
				if mode == "bad-auth" || mode == "denied" {
					want = exitNoPerm
				}

				if code != want || fileExists(metadata) {
					t.Fatalf("cache refusal %s: exit=%d want=%d %s", mode, code, want, stderr)
				}
			}
		})
	}
	if fixture.writes.Load() != writes {
		t.Fatal("cache lookup published registry content")
	}
}

// The cold path must import the authenticated parent locally, run the real
// native builder after registry shutdown, and leave only a staged OCI layout.
func TestPreparedInputs_ColdOfflineNativeBuild(t *testing.T) {
	requireTool(t, "buildah")
	fixture := newPrivateInputRegistry(t)
	parent := fixture.seed(t, "parent", strings.Repeat("a", 40))
	build := preparedBuildJSON(t, fixture, parent, false)
	dir := t.TempDir()
	auth := fixture.authFile(t, "fixture")
	if _, stderr, code := run(t, runOpts{dir: dir}, append(preparedInputArgs(build, "fetch-inputs"), "--auth-file", auth)...); code != 0 {
		t.Fatalf("cold input fetch: exit=%d %s", code, stderr)
	}
	fixture.server.Close()
	if err := os.Mkdir(filepath.Join(dir, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"Containerfile": "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nCOPY payload /payload\n",
		"payload":       "offline-parent-build\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "source", path), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	args := append(preparedInputArgs(build, "build-prepared"), "--release-tag", "v1.2.3",
		"--created", "2026-11-06T00:00:00Z", "--metadata-dir", "staged")
	_, stderr, code := run(t, runOpts{dir: dir}, args...)
	if code != 0 {
		t.Fatalf("cold offline build: exit=%d %s", code, stderr)
	}
	metadata := filepath.Join(dir, "staged", "base-arch-"+runtime.GOARCH, "base-"+runtime.GOARCH+".json")
	if !fileExists(metadata) {
		t.Fatal("cold offline build did not stage metadata")
	}
	layout := filepath.Join(dir, "staged", "base-arch-"+runtime.GOARCH, "layout")
	output := filepath.Join(dir, "extracted")
	_, stderr, code = run(t, runOpts{dir: dir}, "container", "layout", "extract-files",
		"--layout-dir", layout, "--output-dir", output, "--paths", "/payload")
	if code != 0 || readFile(t, filepath.Join(output, "payload")) != "offline-parent-build\n" {
		t.Fatalf("cold output payload: exit=%d %s", code, stderr)
	}
}
