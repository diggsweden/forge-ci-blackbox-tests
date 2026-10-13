<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Release shapes

The cascade tests split on how the release artifact comes to exist. That is
the axis behind `flow_artifact_first`, `flow_container_first`, and
`container_validate_artifacts`.

| Shape | What ships | Ecosystems | Covered by |
|---|---|---|---|
| **artifact-first** | the built file itself (jar, tarball, cross-compiled binary), signed + attached to the release | maven-app, maven-lib, gradle, npm, go, cargo | `flow_artifact_first_test.go` |
| **container-first (compiled)** | an image whose Containerfile *compiles* the binary; the binary is extracted from an `export-binary` stage as a byproduct | go, cargo only | `flow_container_first_test.go` |
| **container-packaging** | an image that COPYs an already-built artifact in, with no binary extraction | maven-app, npm, gradle (plus any artifact-first ecosystem opting into a container) | `container_validate_artifacts_test.go` (the forge-ci presence gate; the buildah COPY itself is workflow glue) |

Two consequences explain what looks like missing coverage:

- **NPM has no app/lib split.** The engine models a build-type only for Maven;
  `NPMConfig` carries none. Every NPM project releases the same way, so there
  is one NPM cascade, not two. An NPM "application" only differs by running its
  package.json build script first, which `build_type_test.go` covers.
- **Maven applications and libraries both have artifact-first JAR paths.** The
  application main JAR can be attached to the release even though applications
  are blocked from Maven Central and omitted from forge package publishing. A
  Maven project may additionally declare a container-packaging path. The
  container-first binary-extraction shape never applies to the JVM because
  there is no single static binary to extract.
