// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformExtractArchive_UnpacksXzWithoutTheHostsXz: an upstream release
// such as cargo-cyclonedx's ships only .tar.xz, and the engine unpacks it, top
// directory dropped, with no xz on the PATH it runs with.
func TestPlatformExtractArchive_UnpacksXzWithoutTheHostsXz(t *testing.T) {
	t.Parallel()

	requireTool(t, "tar")
	requireTool(t, "xz")

	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "tool-x86_64"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(src, "tool-x86_64", "tool"), []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "tool.tar.xz")
	if out, err := toolCommand(t, "", nil, "tar", "-cJf", archive, "-C", src, "tool-x86_64").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}

	dest := filepath.Join(t.TempDir(), "out")

	_, stderr, code := run(t, runOpts{env: map[string]string{"PATH": t.TempDir()}},
		"platform", "extract-archive", "--archive", archive, "--destination", dest)
	if code != 0 {
		t.Fatalf("extract-archive exit=%d stderr=%s", code, stderr)
	}

	if got, err := os.ReadFile(filepath.Join(dest, "tool")); err != nil || string(got) != "binary" {
		t.Fatalf("tool = %q, %v", got, err)
	}

	_, stderr, code = run(t, runOpts{}, "platform", "extract-archive", "--archive", filepath.Join(src, "tool.zip"), "--destination", dest)
	if code != exitUsage {
		t.Fatalf("a .zip: exit=%d, want usage %d; stderr=%s", code, exitUsage, stderr)
	}
}
