// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These advisory commands inspect declared Containerfiles without building or
// pulling their images. A warning must not turn into a failing exit status.
func TestContainerValidate_AdvisoryWarnings(t *testing.T) {
	t.Parallel()

	const artifact = "artifacts:\n  - name: app\n    project-type: maven\n    working-directory: .\n"
	const container = "containers:\n  - name: app\n    container-file: Containerfile\n"
	const fromArtifact = artifact + "containers:\n  - name: app\n    from: [app]\n    container-file: Containerfile\n"

	for _, tc := range []struct {
		name, verb, declaration, file string
		warnings                      []string
		unchecked                     string
	}{
		{"short base with digest", "image-names", container,
			"FROM eclipse-temurin@sha256:0123abcd\n", []string{
				"Containerfile:1", "`eclipse-temurin@sha256:0123abcd` without a registry",
				"docker.io/library/eclipse-temurin@sha256:0123abcd", "name-the-registry-of-an-image",
			}, ""},
		{"argument and external copy", "image-names", container,
			"ARG RUNTIME=eclipse-temurin:21-jre\nFROM docker.io/library/maven:3 AS build\nFROM ${RUNTIME}\n" +
				"COPY --from=build /app.jar /app.jar\nCOPY --from=bitnami/kubectl:1.31 /kubectl /kubectl\n", []string{
				"Containerfile:3", "line 3: eclipse-temurin:21-jre", "docker.io/library/eclipse-temurin:21-jre",
				"line 5: bitnami/kubectl:1.31", "docker.io/bitnami/kubectl:1.31",
			}, ""},
		{"qualified images and stages", "image-names", container,
			"FROM docker.io/library/golang:1.27 AS build\nFROM localhost:5000/tools AS tools\nFROM scratch\n" +
				"COPY --from=build /app /app\nCOPY --from=1 /tool /tool\nCOPY --from=ghcr.io/org/certs:1 /certs /certs\n", nil, ""},
		{"unknown argument", "image-names", container, "ARG BASE\nFROM ${BASE}\n", nil,
			"Containerfile line 2: `${BASE}` not checked for a registry"},
		{"undeclared short image", "image-names", "", "FROM eclipse-temurin:21\n", nil, ""},
		{"artifact rebuilt", "rebuilds", fromArtifact,
			"FROM eclipse-temurin:21 AS build\nCOPY . .\nRUN --mount=type=cache,target=/root/.m2 \\\n    ./mvnw -B clean package\nFROM eclipse-temurin:21\nCOPY --from=build target/app.jar /app.jar\n",
			[]string{"Containerfile:3", "./mvnw -B clean package", `container "app"`, "use-the-built-artifact-in-the-image"}, ""},
		{"artifact copied", "rebuilds", fromArtifact,
			"FROM eclipse-temurin:21\nCOPY target/app.jar /app.jar\n", nil, ""},
		{"Go tool installed", "rebuilds", strings.Replace(fromArtifact, "project-type: maven", "project-type: go", 1),
			"FROM golang:1.27\nRUN go install example.com/tool@v1\nCOPY dist/app /app\n", nil, ""},
		{"Go artifact rebuilt", "rebuilds", strings.Replace(fromArtifact, "project-type: maven", "project-type: go", 1),
			"FROM golang:1.27\nCOPY . .\nRUN go build -o /app ./cmd/app\n", []string{"Containerfile:3", "go build -o /app ./cmd/app"}, ""},
		{"build comment", "rebuilds", fromArtifact,
			"FROM eclipse-temurin:21\n# RUN ./mvnw package\nCOPY target/app.jar /app.jar\n", nil, ""},
		{"no artifact dependency", "rebuilds", artifact + container,
			"FROM eclipse-temurin:21\nRUN ./mvnw package\n", nil, ""},
		{"undeclared build", "rebuilds", "", "FROM eclipse-temurin:21\nRUN ./mvnw package\n", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "Containerfile"), []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}

			if tc.declaration != "" {
				if err := os.MkdirAll(filepath.Join(dir, ".forge-ci"), 0o755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(dir, ".forge-ci", "artifacts.yml"), []byte(tc.declaration), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			stdout, stderr, code := run(t, runOpts{dir: dir}, "container", "validate", tc.verb)
			if code != 0 {
				t.Fatalf("advisory exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}

			output := stdout + stderr
			if tc.unchecked != "" {
				assertContains(t, "unchecked image", output, tc.unchecked)
			}

			if len(tc.warnings) == 0 {
				if strings.Contains(output, "Warning") {
					t.Fatalf("unexpected warning:\n%s", output)
				}

				return
			}

			assertContains(t, "warning annotation", output, "Warning")

			for _, want := range tc.warnings {
				assertContains(t, "advisory warning", output, want)
			}
		})
	}
}
