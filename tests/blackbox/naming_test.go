// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type commandGroupDisposition struct {
	covered bool
	reason  string
}

// commandGroupCoverage is the reviewed disposition for every top-level group.
// TestNaming_TopLevelGroupsHaveCoverageDisposition compares it to the binary,
// so both a new command and a stale entry fail closed.
func commandGroupCoverage() map[string]commandGroupDisposition {
	return map[string]commandGroupDisposition{
		"artifact":  {covered: true, reason: "artifact_digest_test.go"},
		"build":     {covered: true, reason: "build_* and flow_*"},
		"config":    {covered: true, reason: "config_*"},
		"container": {covered: true, reason: "container_* and flow_container_first_test.go"},
		"doctor":    {covered: true, reason: "doctor_test.go"},
		"init":      {covered: false, reason: "reads the examples from a forge-ci mirror over git; forge-ci's consumerinit tests cover it"},
		"lint":      {covered: false, reason: "Swift lint wrappers require a macOS toolchain"},
		"plan":      {covered: true, reason: "version_snapshot_test.go"},
		"platform":  {covered: true, reason: "platform_checkout_test.go"},
		"publish":   {covered: true, reason: "publish_validate_test.go"},
		"release":   {covered: true, reason: "release_* and flow_*"},
		"report":    {covered: true, reason: "report_test.go"},
		"sbom":      {covered: true, reason: "sbom_* and flow_*"},
		"security":  {covered: false, reason: "scanner execution belongs to runtime-image and live integration gates"},
		"toolchain": {covered: false, reason: "installers mutate the host and require networked provider inputs"},
		"validate":  {covered: true, reason: "validate_*"},
		"version":   {covered: true, reason: "version_*"},
	}
}

// commandGroups are the real forge-ci groups a per-command file may use.
func commandGroups() []string {
	return slices.Sorted(maps.Keys(commandGroupCoverage()))
}

// infraFiles carry plain nouns because they are not about one command.
func infraFiles() []string {
	return []string{
		"main_test.go",
		"helpers_test.go",
		"egress_test.go",
		"keys_test.go",
		"naming_test.go",
		"fixtures_hygiene_test.go",
		"gradle_fixtures_test.go",
	}
}

// crossVerbFiles exercise a cascade or a property that spans commands, so no
// single command group names them.
func crossVerbFiles() []string {
	return []string{
		"cli_exit_codes_test.go",
		"reproducibility_test.go",
	}
}

func TestNaming_TopLevelGroupsHaveCoverageDisposition(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := run(t, runOpts{}, "--help")
	if code != 0 {
		t.Fatalf("forge-ci --help exit %d\nstderr: %s", code, stderr)
	}

	actual := map[string]struct{}{}
	inCommands := false
	for line := range strings.SplitSeq(stdout, "\n") {
		switch strings.TrimSpace(line) {
		case "COMMANDS:":
			inCommands = true

			continue
		case "GLOBAL OPTIONS:":
			inCommands = false
		}
		if !inCommands {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "help," {
			continue
		}

		actual[fields[0]] = struct{}{}
	}

	dispositions := commandGroupCoverage()
	for group := range actual {
		if _, ok := dispositions[group]; !ok {
			t.Errorf("top-level command %q has no explicit covered/excluded disposition", group)
		}
	}
	for group, disposition := range dispositions {
		if _, ok := actual[group]; !ok {
			t.Errorf("coverage disposition for removed top-level command %q is stale", group)
		}
		if strings.TrimSpace(disposition.reason) == "" {
			t.Errorf("top-level command %q has no coverage reason", group)
		}
		if disposition.covered && strings.Contains(strings.ToLower(disposition.reason), "require") {
			t.Errorf("covered top-level command %q has an exclusion-like reason %q", group, disposition.reason)
		}
	}
}

// TestNaming_TestFileNamesFollowConvention keeps `ls tests/blackbox` usable as
// the index of this suite.
//
// docs/layout.md states the rule -- infra files take a plain noun, everything else
// leads with the forge-ci command group it exercises -- and this is what
// makes the statement true. Two hand-maintained listings in the README drifted
// from the directory before they were replaced by the rule plus this guard;
// the naming convention is the only index that cannot go stale, and it is
// worth nothing if it is not actually followed.
func TestNaming_TestFileNamesFollowConvention(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(filepath.Join(suiteDir, "tests", "blackbox"))
	if err != nil {
		t.Fatalf("read tests/blackbox: %v", err)
	}

	groups := commandGroups()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}

		name := e.Name()

		if slices.Contains(infraFiles(), name) || slices.Contains(crossVerbFiles(), name) {
			continue
		}

		if strings.HasPrefix(name, "flow_") {
			continue
		}

		// <group>_<feature>_test.go, or just <group>_test.go when the group has
		// a single test file (doctor, report).
		stem := strings.TrimSuffix(name, "_test.go")

		group, _, hasFeature := strings.Cut(stem, "_")
		if !hasFeature {
			group = stem
		}

		if slices.Contains(groups, group) {
			continue
		}

		t.Errorf(
			"%s does not say which forge-ci command it exercises.\n"+
				"    Name it <command-group>_<feature>_test.go, where <command-group> is one\n"+
				"    of: %s.\n"+
				"    If it genuinely spans commands, prefix it flow_ or add it to\n"+
				"    crossVerbFiles(); if it is suite infrastructure, add it to infraFiles().\n"+
				"    If the CLI grew a new command group, add its covered/excluded disposition to commandGroupCoverage().",
			name, strings.Join(groups, ", "),
		)
	}
}
