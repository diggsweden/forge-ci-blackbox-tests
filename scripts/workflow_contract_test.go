// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

package scripts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The compatibility workflow keeps the suite's repository/ref overrides, so
// the engine workflows can keep their immutable suite pin while this suite
// tracks another engine. A fork may change the literal fallback coordinates
// without failing this check. Forgejo gives its workflow directory precedence
// when both provider layers are kept, so the active file is the one checked.
func TestCompatibilityWorkflowKeepsDriftTargetOverrides(t *testing.T) {
	t.Parallel()

	workflow := filepath.Join("..", ".github", "workflows", "integration.yml")
	if info, err := os.Stat(filepath.Join("..", ".forgejo", "workflows")); err == nil && info.IsDir() {
		workflow = filepath.Join("..", ".forgejo", "workflows", "integration.yml")
	}

	body, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read the active compatibility workflow: %v", err)
	}

	for _, guard := range []string{
		"DEFAULT_REPOSITORY: ${{ vars.FORGE_CI_REPOSITORY || ",
		"DEFAULT_REF: ${{ vars.FORGE_CI_REF || ",
		"inputs['forge-ci-ref'] || vars.FORGE_CI_REF || ",
	} {
		if !strings.Contains(string(body), guard) {
			t.Errorf("%s is missing the primary-ref guard %q", workflow, guard)
		}
	}
}
