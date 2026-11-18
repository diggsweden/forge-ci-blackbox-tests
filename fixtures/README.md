# Native project fixtures

Each directory is a disposable project used by the black-box suite. Tests copy
the project into a temporary directory before building or changing it.

Publication fixtures:

| Directory | What it exercises |
|---|---|
| `gradle-library` | JVM publication with POM metadata, module metadata, sources and javadoc; also reused for snapshots. |
| `gradle-multi-library` | Two independent publications. Refusal tests alter only the second module's version or coordinates. |
| `android-library` | Real Android SDK compilation, AAR packaging, Build SBOM, stable export and snapshot export in a pinned SDK container. |
| `maven-central-snapshot` | Modern Central plugin snapshot routing and authentication against a local test registry. |
| `maven-snapshot-guard` | A stable Maven project that must be refused by the snapshot publication path before any registry request. |
| `maven-environment-profile` | A snapshot whose credential-activated profile resolves a stable version; deployment must recheck and refuse before contacting the registry. |

The Gradle publication fixtures share the vendored wrapper scripts and JAR from
`gradle-hello`. `copyGradleFixture` adds these to the temporary project without
duplicating third-party binaries in Git. A fixture's own wrapper properties
take precedence; Android pins Gradle 8.11.1 for its AGP/SDK combination.

The Android Containerfile expects the test to supply the current `forge-ci`
binary. It uses the suite's isolated Buildah storage and installs no host SDK.

The Maven registry URL is a `fixture.registry` property supplied by each test.
Its default is deliberately non-routable, and fixture credentials come from
the test environment rather than checked-in secrets.
