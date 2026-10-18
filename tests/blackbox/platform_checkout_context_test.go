// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"fmt"
	"net/http"
	"net/http/cgi" //nolint:gosec // loopback fixture using the same Git backend as serveGitHTTP.
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

type checkoutMetadataRequest struct {
	server, uri, authorization, privateToken, jobToken string
}

func checkoutMetadataServer(t *testing.T, serverName string, requests chan<- checkoutMetadataRequest) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- checkoutMetadataRequest{serverName, r.RequestURI, r.Header.Get("Authorization"), r.Header.Get("PRIVATE-TOKEN"), r.Header.Get("JOB-TOKEN")}:
		default:
			t.Error("unexpected repeated metadata lookup")
		}

		w.Header().Set("Content-Type", "application/json")
		// Unsupported object formats stop checkout before Git or filesystem
		// mutation. GitHub has no format field: its SHA-1 default instead
		// disagrees with the explicit SHA-256 ref used by the test.
		_, _ = w.Write([]byte(`{"object_format_name":"invalid","repository_object_format":"invalid"}`))
	}))
	t.Cleanup(server.Close)

	return server
}

func TestPlatformCheckout_MetadataUsesCheckoutContext(t *testing.T) {
	t.Parallel()

	for _, forge := range []string{"github", "forgejo", "gitlab"} {
		for _, mode := range []string{"ambient at issuer", "ambient at another server", "operator file", "empty file", "explicit object format", "API PAT"} {
			if mode == "API PAT" && forge != "gitlab" {
				continue
			}
			t.Run(forge+"/"+mode, func(t *testing.T) {
				t.Parallel()

				requests := make(chan checkoutMetadataRequest, 4)
				native := checkoutMetadataServer(t, "native", requests)
				target := checkoutMetadataServer(t, "target", requests)
				server, wantedServer := target.URL, "target"
				if mode == "ambient at issuer" || mode == "empty file" {
					server, wantedServer = native.URL, "native"
				}

				repository, uri := "MixedOrg/My.Repo", "/api/v3/repos/MixedOrg/My.Repo"
				env := map[string]string{"PATH": t.TempDir(), "FORGE_CI_PROVIDER": forge}
				switch forge {
				case "github":
					env["GITHUB_ACTIONS"], env["GITHUB_SERVER_URL"] = "true", native.URL
					env["GITHUB_API_URL"], env["GITHUB_TOKEN"] = native.URL+"/api/v3", "ambient-canary"
				case "forgejo":
					env["GITHUB_ACTIONS"], env["FORGEJO_ACTIONS"] = "true", "true"
					env["FORGEJO_SERVER_URL"], env["FORGEJO_TOKEN"] = native.URL, "ambient-canary"
					uri = "/api/v1/repos/MixedOrg/My.Repo"
				case "gitlab":
					env["GITLAB_CI"], env["CI_SERVER_URL"] = "true", native.URL
					env["CI_JOB_TOKEN"] = "ambient-canary"
					if slices.Contains([]string{"API PAT", "operator file", "empty file"}, mode) {
						env["GITLAB_TOKEN"] = "api-canary"
					}
					repository, uri = "Group/Sub-Group/My.Repo", "/api/v4/projects/Group%2FSub-Group%2FMy.Repo"
				}

				root := t.TempDir()
				args := []string{"--runner", "local", "platform", "checkout", "--repository", repository,
					"--server-url", server, "--ref", strings.Repeat("a", 64), "--workspace", filepath.Join(root, "checkout")}
				secret := ""
				if mode == "API PAT" {
					secret = "api-canary"
				}
				if mode == "ambient at issuer" {
					secret = "ambient-canary"
				}
				if mode == "operator file" || mode == "empty file" {
					if mode == "operator file" {
						secret = "operator-canary"
					}
					file := filepath.Join(t.TempDir(), "token")
					if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--token-file", file)
				}
				if mode == "explicit object format" {
					// Deliberately disagree with the ref so no Git process can run.
					args = append(args, "--object-format", "sha1")
				}

				_, stderr, code := run(t, runOpts{env: env}, args...)
				if (code != exitUsage && code != exitValidation) || !strings.Contains(stderr, "object format") {
					t.Fatalf("metadata preflight: exit=%d stderr=%s", code, stderr)
				}
				if strings.Contains(stderr, "ambient-canary") || strings.Contains(stderr, "operator-canary") {
					t.Fatal("metadata refusal disclosed a credential")
				}

				if mode == "explicit object format" {
					if len(requests) != 0 {
						t.Fatal("object-format override performed metadata I/O")
					}
				} else {
					if len(requests) != 1 {
						t.Fatalf("metadata requests=%d, want exactly one", len(requests))
					}
					got := <-requests
					want := expectedCheckoutMetadataAuth(checkoutMetadataRequest{server: wantedServer, uri: uri}, forge, mode, secret)
					if got != want {
						t.Errorf("metadata context=%+v, want %+v", got, want)
					}
				}

				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 {
					t.Fatalf("metadata refusal mutated workspace: entries=%v err=%v", entries, err)
				}
			})
		}
	}
}

func TestPlatformCheckout_PrivateMetadataAndGitShareContext(t *testing.T) {
	t.Parallel()

	for _, forge := range []string{"github", "forgejo", "gitlab"} {
		t.Run(forge, func(t *testing.T) {
			t.Parallel()

			format, repository, apiPath := "sha256", "MixedOrg/My.Repo", "/api/v1/repos/MixedOrg/My.Repo"
			if forge == "github" {
				format, apiPath = "sha1", "/api/v3/repos/MixedOrg/My.Repo"
			} else {
				requireGitSHA256(t)
			}
			if forge == "gitlab" {
				repository, apiPath = "Group/Sub-Group/My.Repo", "/api/v4/projects/Group%2FSub-Group%2FMy.Repo"
			}

			_, bare, sha := seedForgeRepo(t, format)
			root := filepath.Dir(filepath.Dir(bare))
			renamed := filepath.Join(root, filepath.FromSlash(repository)+".git")
			if err := os.MkdirAll(filepath.Dir(renamed), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(bare, renamed); err != nil {
				t.Fatal(err)
			}

			var metadataCalls, gitCalls atomic.Int64
			gitHandler := &cgi.Handler{Path: lookupTool("git"), Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == apiPath {
					metadataCalls.Add(1)
					want := expectedCheckoutMetadataAuth(checkoutMetadataRequest{}, forge, "operator file", "operator-canary")
					if r.Header.Get("Authorization") != want.authorization || r.Header.Get("PRIVATE-TOKEN") != want.privateToken {
						http.Error(w, "metadata credential mismatch", http.StatusForbidden)

						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"object_format_name":%q,"repository_object_format":%q}`, format, format)

					return
				}
				gitCalls.Add(1)
				_, password, ok := r.BasicAuth()
				if !ok || password != "operator-canary" {
					http.Error(w, "Git credential mismatch", http.StatusForbidden)

					return
				}
				gitHandler.ServeHTTP(w, r)
			}))
			defer server.Close()

			ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("checkout contacted the ambient forge")
				w.WriteHeader(http.StatusForbidden)
			}))
			defer ambient.Close()

			env := repositoryFlowContext(forge, "Wrong/Ambient", "Wrong")
			env["GITHUB_SERVER_URL"], env["GITHUB_API_URL"] = ambient.URL, ambient.URL+"/api/v3"
			env["FORGEJO_SERVER_URL"], env["CI_SERVER_URL"] = ambient.URL, ambient.URL
			env["FORGE_CI_PROVIDER"] = forge
			env["CI_TOKEN"], env["GITLAB_TOKEN"] = "ambient-canary", "ambient-api-canary"
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("operator-canary"), 0o600); err != nil {
				t.Fatal(err)
			}
			workspace := filepath.Join(t.TempDir(), "checkout")
			result := repositoryFlowJSON(t, runOpts{env: env}, "platform", "checkout", "--repository", repository,
				"--server-url", server.URL, "--ref", "v1.0.0", "--workspace", workspace, "--token-file", token)
			if result["checkout-sha"] != sha || gitAt(t, workspace, "rev-parse", "HEAD") != sha || gitAt(t, workspace, "rev-parse", "--show-object-format") != format {
				t.Fatalf("checkout lost the source identity or format: %+v", result)
			}
			if metadataCalls.Load() != 1 || gitCalls.Load() == 0 {
				t.Fatalf("expected metadata then Git: metadata=%d Git=%d", metadataCalls.Load(), gitCalls.Load())
			}
			if remote := gitAt(t, workspace, "remote", "get-url", "origin"); remote != server.URL+"/"+repository+".git" {
				t.Fatalf("source spelling changed: %s", remote)
			}
			config := gitAt(t, workspace, "config", "--local", "--list")
			if strings.Contains(config, "operator-canary") || strings.Contains(strings.ToLower(config), "extraheader") {
				t.Fatal("checkout persisted authentication")
			}
		})
	}
}

func TestPlatformCheckout_MetadataHonorsEquivalentServerURL(t *testing.T) {
	t.Parallel()

	requests := make(chan checkoutMetadataRequest, 4)
	native := checkoutMetadataServer(t, "native", requests)
	runnerServer := strings.Replace(native.URL, "127.0.0.1", "localhost", 1)
	targetServer := strings.Replace(runnerServer, "localhost", "LOCALHOST", 1)
	root := t.TempDir()
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": runnerServer,
		"GITHUB_API_URL": native.URL + "/custom-api", "GITHUB_TOKEN": "ambient-canary",
		"PATH": t.TempDir(),
	}

	_, stderr, code := run(t, runOpts{env: env}, "--runner", "local", "platform", "checkout",
		"--repository", "MixedOrg/My.Repo", "--server-url", targetServer,
		"--ref", strings.Repeat("a", 64), "--workspace", filepath.Join(root, "checkout"))
	if code != exitValidation || !strings.Contains(stderr, "object format") || len(requests) != 1 {
		t.Fatalf("metadata preflight: exit=%d requests=%d stderr=%s", code, len(requests), stderr)
	}

	got := <-requests
	if got.uri != "/custom-api/repos/MixedOrg/My.Repo" || got.authorization != "Bearer ambient-canary" {
		t.Fatalf("equivalent server lost its API configuration: %+v", got)
	}

	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("metadata refusal mutated workspace: entries=%v err=%v", entries, err)
	}
}

func expectedCheckoutMetadataAuth(want checkoutMetadataRequest, forge, mode, secret string) checkoutMetadataRequest {
	if secret == "" {
		return want
	}

	switch forge {
	case "github":
		want.authorization = "Bearer " + secret
	case "forgejo":
		want.authorization = "token " + secret
	case "gitlab":
		if mode == "ambient at issuer" {
			want.jobToken = secret
		} else {
			want.privateToken = secret
		}
	}

	return want
}
