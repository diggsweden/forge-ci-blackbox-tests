// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"os"
	"path/filepath"
	"testing"
)

// Gradle projects share the existing vendored wrapper, but can pin different
// distributions in their own properties. No third-party wrapper is duplicated.
func copyGradleFixture(t *testing.T, name string) string {
	t.Helper()
	project := copyTree(t, fixture(name))
	for _, relative := range []string{"gradlew", "gradlew.bat", "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.jar.sha256", "gradle/wrapper/gradle-wrapper.properties"} {
		destination := filepath.Join(project, relative)
		if fileExists(destination) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(fixture("gradle-hello"), relative)
		info, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		if copyErr := copyFile(source, destination, info.Mode().Perm()); copyErr != nil {
			t.Fatal(copyErr)
		}
	}

	return project
}
