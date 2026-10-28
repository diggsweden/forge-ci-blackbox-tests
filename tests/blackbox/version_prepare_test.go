// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Black-box coverage for the release PREPARE flow around the promote test's
// happy path: derive-release input validation, the Forgejo output sink,
// changelog rendering (both backends, with secret-hygiene booby traps), and
// the full commit-changelog-release orchestration — real git, real SSH
// commit signing, a loopback SSH host-key handshake, and a fake `ssh`
// transport serving git-receive-pack / git-upload-pack from a local bare repo.
package blackbox

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// writeFakeTool writes an executable shell script into dir.
func writeFakeTool(t *testing.T, dir, name, body string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+body), 0o755); err != nil { //nolint:gosec // test fixture must be executable.
		t.Fatal(err)
	}
}

// shellQuote single-quotes s for a fake tool script, so a temp path with
// spaces, quotes or `$` stays one literal word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// suitePATH returns the PATH the run() helper would compute, so fake-tool
// dirs can be PREPENDED without losing the mise-augmented lookup.
func suitePATH() string { return misePath(os.Getenv("PATH")) }

// --- G4: derive-release rejects malformed refs, and says why -------------

func TestDeriveRelease_RejectsInvalidRefs(t *testing.T) {
	for _, invalid := range []string{
		"v1.2.3",                      // plain tag, not a release request
		"release-request/v1.2.3-rc1",  // pre-release
		"release-request/v1.2.3+meta", // build metadata
		"release-request/",            // empty version
	} {
		_, stderr, code := run(t, runOpts{dir: t.TempDir()},
			"version", "derive-release",
			"--ref-name", invalid,
			"--require-release-request", "--release-policy", "stable",
			"--trailer-mode", "coauthor-only")
		if code != exitValidation {
			t.Errorf("derive-release ref %q: exit %d, want 1 (EX_VALIDATION); a usage error or a crash must not stand in for the refusal", invalid, code)

			continue
		}

		// Rejecting for the WRONG reason must not pass as validation; both
		// rejection variants name the expected format.
		assertContains(t, "rejection of "+invalid, stderr, "vMAJOR.MINOR.PATCH")
	}
}

// --- G3: the Forgejo output sink emits the same keys as the GitHub one ---

func TestDeriveRelease_ForgejoOutputSinkKeyParity(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		makeGPGSignedTag(t, runGit, repo, key, "release-request/v2.0.0")
	})

	outFile := filepath.Join(t.TempDir(), "forgejo-output")
	_, stderr, code := run(t, runOpts{
		dir: repo,
		env: map[string]string{
			"FORGE_CI_RUNNER":  "forgejo",
			"FORGEJO_REF_NAME": "release-request/v2.0.0",
			"FORGEJO_OUTPUT":   outFile,
			"GNUPGHOME":        key.gnupgHome,
		},
	}, "version", "derive-release")
	if code != 0 {
		t.Fatalf("derive-release (forgejo sink) exit %d\nstderr: %s", code, stderr)
	}

	// Same file format, same kebab-case keys as the GitHub sink asserted in
	// the promote test — consumers read these names from workflow outputs.
	outputs := parseGHAOutputs(t, outFile)
	if outputs["release-tag"] != "v2.0.0" {
		t.Errorf("release-tag = %q, want v2.0.0", outputs["release-tag"])
	}

	if outputs["version"] != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", outputs["version"])
	}

	if outputs["release-request"] != "release-request/v2.0.0" {
		t.Errorf("release-request = %q, want release-request/v2.0.0", outputs["release-request"])
	}
}

func TestDeriveRelease_PrereleaseRequiresExplicitPolicy(t *testing.T) {
	t.Parallel()
	requireTool(t, "git")
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)
	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		makeGPGSignedTag(t, runGit, repo, key, "release-request/v2.0.0-beta.1")
	})
	for _, policy := range []string{"stable", "stable-prerelease"} {
		output := filepath.Join(t.TempDir(), "outputs")
		_, stderr, code := run(t, runOpts{dir: repo, env: map[string]string{
			"FORGE_CI_RUNNER": "forgejo", "FORGEJO_OUTPUT": output, "GNUPGHOME": key.gnupgHome,
		}}, "version", "derive-release", "--ref-name", "release-request/v2.0.0-beta.1",
			"--require-release-request", "--release-policy", policy)
		if policy == "stable" {
			if code != exitValidation {
				t.Fatalf("stable policy exit=%d, want validation refusal: %s", code, stderr)
			}

			continue
		}
		if code != 0 {
			t.Fatalf("explicit prerelease policy exit=%d: %s", code, stderr)
		}
		if got := parseGHAOutputs(t, output)["release-tag"]; got != "v2.0.0-beta.1" {
			t.Fatalf("release-tag=%q, want exact prerelease", got)
		}
	}
}

// --- G2: render-changelog backend contract + secret hygiene --------------

// renderFixture builds a real repo (main branch, tracked CHANGELOG.md, bare
// origin) plus fake git-chglog/git-cliff renderers that log their argv and
// booby-trap on inherited secrets.
func renderFixture(t *testing.T) (repo, fakeBin, renderLog string) {
	t.Helper()
	requireTool(t, "git")

	bare := t.TempDir()
	gitAt(t, "", "init", "--bare", bare)

	repo = initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		if err := os.WriteFile(filepath.Join(repo, "CHANGELOG.md"), []byte("# old\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "CHANGELOG.md")
		for _, file := range []string{".chglog/config.yml", ".chglog/body.yml", "cliff.toml", "cliff-body.toml"} {
			full := filepath.Join(repo, file)
			if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("# inert renderer fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			mustGit(t, runGit, "add", file)
		}
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		mustGit(t, runGit, "branch", "-M", "main")
		mustGit(t, runGit, "remote", "add", "origin", bare)
		mustGit(t, runGit, "push", "-q", "origin", "main")
	})

	fakeBin = t.TempDir()
	renderLog = filepath.Join(t.TempDir(), "render.log")

	boobyTrap := `if [ -n "${SSH_SIGNING_KEY:-}" ] || [ -n "${FORGEJO_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "ERROR: renderer inherited a signing/API secret" >&2
  exit 97
fi
`
	writeFakeTool(t, fakeBin, "git-chglog", boobyTrap+`printf 'git-chglog %s\n' "$*" >>`+shellQuote(renderLog)+`
case "$*" in
  *--output*) printf '# v9.9.1\n\n- change\n' >CHANGELOG.md ;;
  *) printf 'body from chglog\n' ;;
esac
`)
	writeFakeTool(t, fakeBin, "git-cliff", boobyTrap+`printf 'git-cliff %s\n' "$*" >>`+shellQuote(renderLog)+`
case "$*" in
  *--output*) printf '# v9.9.2\n\n- cliff change\n' >CHANGELOG.md ;;
  *) printf 'body from cliff\n' ;;
esac
`)

	return repo, fakeBin, renderLog
}

// TestRenderChangelogFixture_BoobyTrapIsArmed is the control for the secret
// hygiene asserted below. That assertion is indirect: the fake renderers exit
// 97 when they see SSH_SIGNING_KEY / FORGEJO_TOKEN / GITHUB_TOKEN, and the test
// concludes the scrub worked because render-changelog exited 0.
//
// The conclusion only follows if the trap can actually fire. A mangled trap —
// a bad quote, a renamed variable, a `set -e` interaction — makes the renderer
// exit 0 regardless, and the hygiene test passes at full confidence while
// checking nothing. Run the fixture's own renderer directly with a secret in
// the environment and require the refusal.
func TestRenderChangelogFixture_BoobyTrapIsArmed(t *testing.T) {
	t.Parallel()

	_, fakeBin, _ := renderFixture(t)

	for _, secret := range []string{"SSH_SIGNING_KEY", "FORGEJO_TOKEN", "GITHUB_TOKEN"} {
		t.Run(secret, func(t *testing.T) {
			for _, tool := range []string{"git-chglog", "git-cliff"} {
				cmd := toolCommand(t, t.TempDir(), map[string]string{secret: "leaked"},
					filepath.Join(fakeBin, tool), "--version")

				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("%s did not refuse with %s set — the trap is not armed, so "+
						"TestRenderChangelog_BackendsAndSecretHygiene proves nothing\noutput: %s", tool, secret, out)
				}

				if !strings.Contains(string(out), "inherited a signing/API secret") {
					t.Errorf("%s failed for some other reason than the trap: %v\n%s", tool, err, out)
				}
			}
		})
	}

	// And the other direction: with no secret set the renderer must run, or
	// the check above would pass for the wrong reason.
	cmd := toolCommand(t, t.TempDir(), nil, filepath.Join(fakeBin, "git-chglog"), "--version")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("renderer refused with a clean environment: %v\n%s", err, out)
	}
}

func TestRenderChangelog_BackendsAndSecretHygiene(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		backend, tag, changelogCfg, bodyCfg, wantBody string
	}{
		{"git-chglog", "v9.9.1", ".chglog/config.yml", ".chglog/body.yml", "body from chglog"},
		{"git-cliff", "v9.9.2", "cliff.toml", "cliff-body.toml", "body from cliff"},
	} {
		t.Run(tc.backend, func(t *testing.T) {
			repo, fakeBin, renderLog := renderFixture(t)
			repositoryURL := "https://forgejo.example/fixture/consumer"

			_, stderr, code := run(t, runOpts{
				dir: repo,
				env: map[string]string{
					"PATH":           fakeBin + string(os.PathListSeparator) + suitePATH(),
					"GITHUB_ACTIONS": "true",
					// The booby trap in the fake renderers proves the
					// binary scrubs these before spawning the renderer.
					"FORGEJO_TOKEN":   "super-secret",
					"SSH_SIGNING_KEY": "-----BEGIN OPENSSH PRIVATE KEY----- trap",
				},
			}, "version", "render-changelog",
				"--changelog-creator", tc.backend,
				"--tag", tc.tag,
				"--repository-url", repositoryURL,
				"--changelog-config", tc.changelogCfg,
				"--commit-body-config", tc.bodyCfg,
				"--commit-trailers", "Release-Request: release-request/"+tc.tag)
			if code != 0 {
				t.Fatalf("render-changelog exit %d\nstderr: %s", code, stderr)
			}

			log := readFile(t, renderLog)
			assertContains(t, "changelog render argv", log, "--config "+tc.changelogCfg)
			assertContains(t, "body render argv", log, "--config "+tc.bodyCfg)
			assertContains(t, "next-tag argv", log, tc.tag)
			if tc.backend == "git-chglog" {
				assertContains(t, "repository URL argv", log, "--repository-url "+repositoryURL)
			} else if strings.Contains(log, "--repository-url") {
				t.Fatalf("git-cliff received git-chglog repository URL flag:\n%s", log)
			}

			msg := readFile(t, filepath.Join(repo, "commit-msg.txt"))
			assertContains(t, "commit subject", msg, "chore(release): bump to "+tc.tag)
			assertContains(t, "commit body", msg, tc.wantBody)
			assertContains(t, "skip-ci marker", msg, "[skip ci]")
			assertContains(t, "release-request trailer", msg, "Release-Request: release-request/"+tc.tag)
		})
	}
}

// --- G5: commit-changelog-release, end to end -----------------------------

// Serve a real loopback SSH handshake: host-key inspection now happens in
// process, so a PATH stub for ssh-keyscan cannot supply the host's identity.
func prepareHostKeyServer(t *testing.T, keyPath string) (string, string) {
	t.Helper()
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var listen net.ListenConfig
	listener, err := listen.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(signer)
			server, _, _, handshakeErr := ssh.NewServerConn(conn, config)
			if handshakeErr == nil {
				_ = server.Close()
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	return "127.0.0.1", port
}

func TestCommitChangelogRelease_SignsPushesAndCleansUp(t *testing.T) {
	t.Parallel()

	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	// Real signing key and host key; derive the fixture's trusted fingerprint
	// from its public-key file, independently of the network handshake.
	keyDir := t.TempDir()
	signKey := filepath.Join(keyDir, "sign_ed25519")
	hostKey := filepath.Join(keyDir, "host_ed25519")

	for _, k := range []string{signKey, hostKey} {
		cmd := toolCommand(t, "", nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "integration", "-f", k)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %s: %v\n%s", k, err, out)
		}
	}

	host, port := prepareHostKeyServer(t, hostKey)
	gitURL := "ssh://git@" + net.JoinHostPort(host, port) + "/itq/example.git"
	fpFields := strings.Fields(outputOrFatal(t, toolCommand(t, "", nil, "ssh-keygen", "-lf", hostKey+".pub")))
	if len(fpFields) < 2 {
		t.Fatalf("ssh-keygen -lf: unexpected output %q", fpFields)
	}

	fingerprint := fpFields[1] // "256 SHA256:... comment (ED25519)"

	bare := t.TempDir()
	gitAt(t, "", "init", "--bare", bare)

	// Repo state as prepare leaves it: tracked-but-modified CHANGELOG plus
	// the rendered commit-msg/body files.
	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		if err := os.WriteFile(filepath.Join(repo, "CHANGELOG.md"), []byte("# old\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "CHANGELOG.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		mustGit(t, runGit, "branch", "-M", "main")
		mustGit(t, runGit, "remote", "add", "origin", bare)
		mustGit(t, runGit, "push", "-q", "origin", "main")
	})

	for name, body := range map[string]string{
		"CHANGELOG.md":    "# v3.0.0\n\n- change\n",
		"commit-msg.txt":  "chore(release): bump to v3.0.0\n\nbody\n\n[skip ci]\n",
		"commit-body.txt": "body\n",
	} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The host key comes from the real handshake above. A fake ssh command
	// serves Git's upload/receive protocol from the bare repository and
	// booby-traps inherited signing material.
	fakeBin := t.TempDir()
	boobyTrap := `if [ -n "${SSH_SIGNING_KEY:-}" ]; then
  echo "ERROR: transport inherited SSH_SIGNING_KEY" >&2
  exit 97
fi
`
	sshConfigCopy := filepath.Join(t.TempDir(), "ssh-config")
	sshConfigPathLog := filepath.Join(t.TempDir(), "ssh-config-path")
	writeFakeTool(t, fakeBin, "ssh", boobyTrap+fmt.Sprintf(`# Skip ssh options; the trailing argument is the remote command.
config=
while [ $# -gt 0 ]; do
  case "$1" in
    -F) config="${2:?}"; shift 2 ;;
    -o|-i|-l|-p|-E) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done

if [ -z "$config" ]; then
  echo "fake ssh: missing -F config" >&2
  exit 98
fi
if ! grep -Fqx '  HostName %s' "$config" ||
   ! grep -Fqx '  Port %s' "$config" ||
   ! grep -Fqx '  User git' "$config" ||
   ! grep -Fqx '  StrictHostKeyChecking yes' "$config"; then
  echo "fake ssh: generated config does not carry the required endpoint and strict host checking" >&2
  exit 98
fi
printf '%%s\n' "$config" >%s
cp "$config" %s

target="${1:?}"
shift
if [ "$target" != "git@%s" ]; then
  echo "fake ssh: unexpected target: $target" >&2
  exit 98
fi
if [ $# -eq 0 ]; then
  exit 1
fi
cmd="$1"
case "${cmd}" in
  git-receive-pack*) exec git receive-pack %s ;;
  git-upload-pack*) exec git upload-pack %s ;;
  *) echo "fake ssh: unexpected command: ${cmd}" >&2; exit 1 ;;
esac
`, host, port, shellQuote(sshConfigPathLog), shellQuote(sshConfigCopy), host, shellQuote(bare), shellQuote(bare)))

	outFile := filepath.Join(t.TempDir(), "outputs")
	env := map[string]string{
		"PATH":                             fakeBin + string(os.PathListSeparator) + suitePATH(),
		"GITHUB_ACTIONS":                   "true",
		"GITHUB_OUTPUT":                    outFile,
		"SSH_SIGNING_KEY":                  readFile(t, signKey),
		"GIT_USER_NAME":                    "Suite Release Bot",
		"GIT_USER_EMAIL":                   "release-bot@test.example",
		"RELEASE_GIT_URL":                  gitURL,
		"RELEASE_GIT_HOST_KEY_FINGERPRINT": fingerprint,
	}
	initial := gitAt(t, repo, "rev-parse", "HEAD")
	wrongPin := strings.Fields(outputOrFatal(t, toolCommand(t, "", nil, "ssh-keygen", "-lf", signKey+".pub")))[1]
	env["RELEASE_GIT_HOST_KEY_FINGERPRINT"] = wrongPin
	_, stderr, code := run(t, runOpts{dir: repo, env: env}, "version", "commit-changelog-release",
		"--tag", "v3.0.0", "--repository", "itq/example")
	if code != exitValidation || !strings.Contains(stderr, "fingerprint mismatch") {
		t.Fatalf("wrong host pin exit=%d, want fingerprint refusal: %s", code, stderr)
	}
	if fileExists(sshConfigPathLog) || gitAt(t, repo, "rev-parse", "HEAD") != initial {
		t.Fatal("wrong host pin reached the Git transport or changed the source")
	}
	env["RELEASE_GIT_HOST_KEY_FINGERPRINT"] = fingerprint
	_, stderr, code = run(t, runOpts{dir: repo, env: env}, "version", "commit-changelog-release",
		"--tag", "v3.0.0", "--repository", "itq/example")
	if code != 0 {
		t.Fatalf("commit-changelog-release exit %d\nstderr: %s", code, stderr)
	}

	head := gitAt(t, repo, "rev-parse", "HEAD")
	if got := gitAt(t, repo, "remote", "get-url", "origin"); got != gitURL {
		t.Errorf("origin URL = %q, want exact validated SSH URL", got)
	}

	// Pushed for real through the fake transport: branch and tag landed in
	// the bare remote at the bump commit.
	if got := gitAt(t, bare, "rev-parse", "refs/heads/main"); got != head {
		t.Errorf("remote main = %s, want bump commit %s", got, head)
	}

	if got := gitAt(t, bare, "rev-list", "-n", "1", "v3.0.0"); got != head {
		t.Errorf("remote tag v3.0.0 = %s, want bump commit %s", got, head)
	}

	// The bump commit is SSH-signed and verifies against the signing key.
	signers := filepath.Join(t.TempDir(), "allowed_signers")
	if err := os.WriteFile(signers, []byte("release-bot@test.example "+strings.TrimSpace(readFile(t, signKey+".pub"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status := gitAt(t, repo, "-c", "gpg.ssh.allowedSignersFile="+signers, "log", "-1", "--format=%G?")
	if status != "G" {
		t.Errorf("bump commit signature status = %q, want G (good)", status)
	}

	// The final tag has its own SSH signature; verifying the commit does not
	// prove the annotated tag object was signed.
	gitAt(t, repo, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+signers, "tag", "-v", "v3.0.0")

	sshConfig := readFile(t, sshConfigCopy)
	assertContains(t, "SSH config hostname", sshConfig, "  HostName "+host+"\n")
	assertContains(t, "SSH config port", sshConfig, "  Port "+port+"\n")
	sshConfigPath := strings.TrimSpace(readFile(t, sshConfigPathLog))
	if !filepath.IsAbs(sshConfigPath) {
		t.Fatalf("fake ssh logged no absolute config path: %q", sshConfigPath)
	}

	// fileExists reports regular files only, so the directory needs a stat.
	if _, statErr := os.Stat(filepath.Dir(sshConfigPath)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("isolated SSH setup was not cleaned up: %s (stat: %v)", filepath.Dir(sshConfigPath), statErr)
	}

	// The rendered message files are consumed, not left in the workspace.
	for _, leftover := range []string{"commit-msg.txt", "commit-body.txt"} {
		if fileExists(filepath.Join(repo, leftover)) {
			t.Errorf("%s must be cleaned up after the release commit", leftover)
		}
	}

	if outputs := parseGHAOutputs(t, outFile); outputs["release-sha"] != head {
		t.Errorf("release-sha output = %q, want %s", outputs["release-sha"], head)
	}
}
