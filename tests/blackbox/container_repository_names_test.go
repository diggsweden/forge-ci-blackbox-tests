// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContainerRepositoryNames_ResolvePublicContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ forge, registry, repository, owner, name, image, want string }{
		{"github", "ghcr.io", "MixedOwner/My.Repo", "MixedOwner", "", "", "ghcr.io/mixedowner/my.repo"},
		{"github", "ghcr.io", "MixedOwner/MyRepo", "MixedOwner", "myrepo", "", "ghcr.io/mixedowner/myrepo"},
		{"forgejo", "registry.example", "Org/App__Tools--CLI", "Org", "Worker", "", "registry.example/org/app__tools--cli/worker"},
		{"gitlab", "registry.gitlab.com", "Group/Sub-Group/My_Repo.v2", "Group/Sub-Group", "", "", "registry.gitlab.com/group/sub-group/my_repo.v2"},
		{"github", "docker.io", "Org/MyRepo", "Org", "", "", "docker.io/org/myrepo"},
		{"github", "docker.io", "Org/MyRepo", "Org", "", "my-image", "docker.io/org/my-image"},
		{"github", "ghcr.io", "Org/.github", "Org", "", "org/github-config", "ghcr.io/org/github-config"},
	} {
		t.Run(tc.forge+"/"+tc.registry+"/"+tc.repository+"/"+tc.image, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := run(t, runOpts{env: map[string]string{"CONTAINER_NAME": tc.name}},
				"--provider", tc.forge, "--runner", "local", "--format", "json", "container", "ref", "resolve",
				"--registry", tc.registry, "--repository", tc.repository, "--repository-owner", tc.owner, "--image-name", tc.image)
			if code != 0 {
				t.Fatalf("resolve: exit=%d: %s", code, stderr)
			}
			var output map[string]string
			if err := json.Unmarshal([]byte(stdout), &output); err != nil {
				t.Fatalf("output=%q: %v", stdout, err)
			}
			if output["name"] != tc.want {
				t.Fatalf("name=%q, want %q", output["name"], tc.want)
			}
		})
	}
}

func TestContainerRepositoryNames_RejectUnicodeFoldAlias(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := run(t, runOpts{}, "--format", "json", "container", "ref", "resolve",
		"--registry", "ghcr.io", "--repository", "Org/Repos", "--repository-owner", "Org", "--name", "repo\u017f")
	if code != exitUsage || !strings.Contains(stderr, "OCI repository") || strings.Contains(stdout, `"name"`) {
		t.Fatalf("invalid sub-name: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestContainerRepositoryNames_ExplicitMappingRequiresPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		expected string
		accepted bool
	}{
		{"", false}, {"ghcr.io/org/github-config", true},
		{"ghcr.io/other/github-config", false}, {"evil.example/org/github-config", false},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			_, stderr, code := run(t, runOpts{}, "container", "validate", "namespace", "--registry", "ghcr.io",
				"--repository", "Org/.github", "--enforce-namespace", "Org", "--image-name", "ghcr.io/org/github-config",
				"--expected-image-repository", tc.expected)
			if (code == 0) != tc.accepted {
				t.Fatalf("exit=%d, want accepted=%v: %s", code, tc.accepted, stderr)
			}
		})
	}
}
