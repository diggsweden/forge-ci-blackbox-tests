<!-- SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# Layout and where a test goes

## Layout

One Go package, one fixtures tree, nothing else.

```text
.
├── README.md
├── go.mod
├── justfile          ← dev-loop recipes (just verify / lint / test)
├── .golangci.yml     ← linter config, sets the blackbox build tag
├── .mise.toml        ← pinned toolchain and lint tools
├── LICENSES/         ← license texts (REUSE)
├── docs/             ← this documentation
├── fixtures/         ← ecosystem test projects, one dir per language/shape
├── scripts/          ← strict-profile contract probe and evidence bounding
└── tests/blackbox    ← the whole suite: one Go package, build tag `blackbox`
```

## Where a test goes

Every file in `tests/blackbox/` is one of three things, and the name says
which:

| Kind | Name | Example |
|---|---|---|
| Infra | a plain noun | `main_test.go`, `helpers_test.go`, `keys_test.go` |
| Per-command | `<command-group>_<feature>_test.go` | `release_sign_cosign_test.go` |
| Cross-verb | `flow_*_test.go`, or a named cross-cutting concern | `flow_artifact_first_test.go`, `reproducibility_test.go` |

`<command-group>` is the forge-ci command the file exercises, so
`ls tests/blackbox` sorts the suite by command and a bare `ls` is the index.
That listing is deliberately not copied into the documentation: a copy has
nothing holding it to the directory, and goes stale unnoticed.

`TestNaming_TestFileNamesFollowConvention` in `naming_test.go` enforces the
table above, so the rule is checked rather than merely stated.

How to write a new test is in [Development](development.md).
