// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func repositoryFlowJSON(t *testing.T, opts runOpts, args ...string) map[string]string {
	t.Helper()

	stdout, stderr, code := run(t, opts, append([]string{"--runner", "local", "--format", "json"}, args...)...)
	if code != 0 {
		t.Fatalf("%v: exit=%d stderr=%s", args, code, stderr)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("JSON output %q: %v", stdout, err)
	}

	return result
}

func repositoryFlowContext(forge, repository, namespace string) map[string]string {
	values := map[string]string{"CONTAINER_NAME": "Worker"}
	if forge == "gitlab" {
		values["GITLAB_CI"], values["CI_SERVER_URL"] = "true", "https://forge.invalid"
		values["CI_PROJECT_PATH"], values["CI_PROJECT_NAMESPACE"] = repository, namespace
		values["CI_PROJECT_URL"] = "https://forge.invalid/" + repository
		values["CI_COMMIT_SHA"], values["CI_COMMIT_REF_NAME"] = strings.Repeat("b", 40), "main"
		values["CI_COMMIT_BRANCH"], values["CI_PIPELINE_SOURCE"] = "main", "push"

		return values
	}

	prefix := "GITHUB_"
	values["GITHUB_ACTIONS"] = "true"
	if forge == "forgejo" {
		prefix = "FORGEJO_"
		values["FORGEJO_ACTIONS"] = "true"
		values["GITHUB_REPOSITORY"], values["GITHUB_REPOSITORY_OWNER"] = "Wrong/Alias", "Wrong"
	}
	values[prefix+"REPOSITORY"], values[prefix+"REPOSITORY_OWNER"] = repository, namespace
	values[prefix+"SERVER_URL"] = "https://forge.invalid"
	values[prefix+"SHA"], values[prefix+"REF_NAME"] = strings.Repeat("b", 40), "main"
	values[prefix+"REF_TYPE"], values[prefix+"EVENT_NAME"] = "branch", "push"

	return values
}

func TestFlow_RepositoryContextThroughPublication(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ forge, repository, namespace, imagePath, mapping string }{
		{"github", "MixedOrg/My.Repo", "MixedOrg", "mixedorg/my.repo/worker", ""},
		{"forgejo", "MixedOrg/App__Tools--CLI", "MixedOrg", "mixedorg/app__tools--cli/worker", ""},
		{"gitlab", "Group/Sub-Group/My_Repo.v2", "Group/Sub-Group", "group/sub-group/my_repo.v2/worker", ""},
		{"github", "MixedOrg/.github", "MixedOrg", "mixedorg/github-config", "mixedorg/github-config"},
	} {
		t.Run(tc.forge+"/"+tc.repository, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int64
			handler := registry.New()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()

			host := server.Listener.Addr().String()
			opts := runOpts{dir: t.TempDir(), env: repositoryFlowContext(tc.forge, tc.repository, tc.namespace)}
			args := []string{"container", "ref", "resolve", "--registry", host}
			if tc.mapping != "" {
				args = append(args, "--image-name", host+"/"+tc.mapping)
			}
			image := repositoryFlowJSON(t, opts, args...)["name"]
			if image != host+"/"+tc.imagePath {
				t.Fatalf("image=%q, want %s/%s", image, host, tc.imagePath)
			}

			args = []string{"container", "validate", "namespace", "--image-name", image,
				"--registry", host, "--enforce-namespace-on", host, "--enforce-namespace", tc.namespace}
			if tc.mapping != "" {
				args = append(args, "--expected-image-repository", host+"/"+tc.mapping)
			}
			if _, stderr, code := run(t, opts, args...); code != 0 {
				t.Fatalf("namespace: exit=%d stderr=%s", code, stderr)
			}

			metadata := repositoryFlowJSON(t, opts, "container", "metadata", "--image-name", image,
				"--tag-rules", "type=ref,event=tag\ntype=raw,value=Release_1", "--emit-labels",
				"--source-ref-name", "v1.2.3", "--source-ref-type", "tag", "--source-revision", strings.Repeat("a", 40),
				"--source-date-epoch", "1700000000", "--oci-description", "fixture", "--oci-license", "MIT")
			var document struct {
				Tags   []string          `json:"tags"`
				Labels map[string]string `json:"labels"`
			}
			if err := json.Unmarshal([]byte(metadata["json"]), &document); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(document.Tags, []string{image + ":v1.2.3", image + ":Release_1"}) || metadata["staging-tag"] != image+":staging-v1.2.3" {
				t.Fatalf("release tag context lost: %+v", metadata)
			}
			if document.Labels["org.opencontainers.image.source"] != "https://forge.invalid/"+tc.repository || document.Labels["org.opencontainers.image.revision"] != strings.Repeat("a", 40) {
				t.Fatalf("source spelling or released revision changed: %+v", document.Labels)
			}

			publishRepositoryFlow(t, opts, image, append(document.Tags, metadata["staging-tag"]), document.Labels, &requests)
		})
	}
}

func publishRepositoryFlow(t *testing.T, opts runOpts, image string, tags []string, labels map[string]string, requests *atomic.Int64) {
	t.Helper()

	child, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	config, err := child.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	config.OS, config.Architecture, config.Config.Labels = "linux", "amd64", labels
	child, err = mutate.ConfigFile(child, config)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := name.NewTag(image+":build", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(seed, child, remote.WithContext(t.Context())); err != nil {
		t.Fatal(err)
	}
	digest, err := child.Digest()
	if err != nil {
		t.Fatal(err)
	}

	markers := filepath.Join(opts.dir, "digests")
	if _, stderr, code := run(t, opts, "container", "write-digest-marker", "--digest", digest.String(), "--digests-dir", markers); code != 0 {
		t.Fatalf("digest marker: exit=%d stderr=%s", code, stderr)
	}
	base := []string{"container", "manifest", "merge", "--image-name", image, "--digests-dir", markers, "--tags"}
	before := requests.Load()
	foreign := strings.SplitN(image, "/", 2)[0] + "/other/app:v1.2.3"
	if _, stderr, code := run(t, opts, append(base, foreign)...); code != exitValidation || requests.Load() != before {
		t.Fatalf("foreign tag was not refused before registry I/O: exit=%d stderr=%s", code, stderr)
	}
	if _, stderr, code := run(t, opts, append(base, strings.Join(tags, "\n"))...); code != 0 {
		t.Fatalf("manifest publication: exit=%d stderr=%s", code, stderr)
	}

	for _, tag := range tags {
		ref, parseErr := name.NewTag(tag, name.Insecure)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		index, fetchErr := remote.Index(ref, remote.WithContext(t.Context()))
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		manifest, manifestErr := index.IndexManifest()
		if manifestErr != nil {
			t.Fatal(manifestErr)
		}
		if len(manifest.Manifests) != 1 || manifest.Manifests[0].Digest != digest {
			t.Fatalf("published %s with wrong children: %+v", tag, manifest)
		}
		stored, imageErr := index.Image(digest)
		if imageErr != nil {
			t.Fatal(imageErr)
		}
		storedConfig, configErr := stored.ConfigFile()
		if configErr != nil {
			t.Fatal(configErr)
		}
		if storedConfig.Config.Labels["org.opencontainers.image.source"] != labels["org.opencontainers.image.source"] {
			t.Fatal("publication changed source identity")
		}
	}
}
