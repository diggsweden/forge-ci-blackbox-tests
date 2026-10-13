// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gpgKey holds a throwaway GPG key plus its isolated GNUPGHOME.
type gpgKey struct {
	gnupgHome   string
	keyID       string
	fingerprint string
	privateASC  string // path to armored private key
	publicASC   string // path to armored public key
}

// signingEnv is what `release sign` and `release gpg import` need: the
// isolated keyring to work in, and the armored private key to import. Every
// caller derived this the same way, reading the key file and handling the
// error inline; asking the key for it says what the test means instead.
//
// Callers needing more variables add to the returned map, which is freshly
// allocated per call.
func (k gpgKey) signingEnv(t *testing.T) map[string]string {
	t.Helper()

	private, err := os.ReadFile(k.privateASC)
	if err != nil {
		t.Fatalf("read armored private key %s: %v", k.privateASC, err)
	}

	return map[string]string{
		"GNUPGHOME":       k.gnupgHome,
		"GPG_PRIVATE_KEY": string(private),
	}
}

// gpgKeyEd25519 and gpgKeyRSA are the key-type lines of a gpg --gen-key
// batch file. ed25519 generates in milliseconds; RSA-2048 takes seconds of
// prime search per key, so only the one row that pins RSA signing uses it.
const (
	gpgKeyEd25519 = "Key-Type: EDDSA\nKey-Curve: ed25519\n"
	gpgKeyRSA     = "Key-Type: RSA\nKey-Length: 2048\n"
)

// bootstrapGPGKey generates a throwaway no-passphrase ed25519 key in an
// isolated GNUPGHOME with ultimate ownertrust. The key is cleaned up
// when the test ends via t.Cleanup.
func bootstrapGPGKey(t *testing.T) gpgKey {
	t.Helper()

	return bootstrapGPGKeyOfType(t, gpgKeyEd25519)
}

// bootstrapRSAGPGKey is bootstrapGPGKey with an RSA-2048 key, for the row
// that keeps RSA signing covered.
func bootstrapRSAGPGKey(t *testing.T) gpgKey {
	t.Helper()

	return bootstrapGPGKeyOfType(t, gpgKeyRSA)
}

func bootstrapGPGKeyOfType(t *testing.T, keyType string) gpgKey {
	t.Helper()
	requireTool(t, "gpg")

	dir := t.TempDir()
	gpgEnv := map[string]string{"GNUPGHOME": dir}
	// gpg starts an agent per keyring; stop it before the directory goes.
	// Not via toolCommand: t.Context() is already cancelled in cleanup.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), toolInspectionTimeout)
		defer cancel()

		gpgconf := lookupTool("gpgconf")
		if gpgconf == "" {
			t.Logf("gpgconf not found; the gpg-agent for %s may outlive the test", dir)

			return
		}

		cmd := exec.CommandContext(ctx, gpgconf, "--kill", "all")
		cmd.Env = isolatedEnv(gpgEnv)
		cmd.WaitDelay = time.Second

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("gpgconf --kill all: %v\n%s", err, out)
		}
	})

	keygen := filepath.Join(dir, "keygen")
	if err := os.WriteFile(keygen, []byte("%no-protection\n"+keyType+`Name-Real: Integration Test
Name-Email: integration@test.example
Expire-Date: 0
%commit
`), 0o600); err != nil {
		t.Fatalf("write keygen: %v", err)
	}

	if out, err := toolCommand(t, "", gpgEnv, "gpg", "--batch", "--gen-key", keygen).CombinedOutput(); err != nil {
		t.Fatalf("gen-key: %v\n%s", err, out)
	}

	// stdout only: gpg's trustdb notices on stderr are not key records.
	colons := outputOrFatal(t, toolCommand(t, "", gpgEnv, "gpg", "--list-secret-keys", "--with-colons"))

	key := gpgKey{gnupgHome: dir}
	for line := range strings.SplitSeq(colons, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 11 {
			continue
		}

		switch fields[0] {
		case "sec":
			if key.keyID == "" {
				key.keyID = fields[4]
			}
		case "fpr":
			if key.fingerprint == "" {
				key.fingerprint = fields[9]
			}
		}
	}

	if key.keyID == "" || key.fingerprint == "" {
		t.Fatalf("could not parse key id / fingerprint from:\n%s", colons)
	}

	// Ultimate ownertrust so signing works without prompts.
	trustCmd := toolCommand(t, "", gpgEnv, "gpg", "--import-ownertrust")
	trustCmd.Stdin = strings.NewReader(key.fingerprint + ":6:\n")

	if out, err := trustCmd.CombinedOutput(); err != nil {
		t.Fatalf("import-ownertrust: %v\n%s", err, out)
	}

	key.privateASC = filepath.Join(dir, "priv.asc")
	exportArmored(t, dir, key.keyID, key.privateASC, "--export-secret-keys")

	key.publicASC = filepath.Join(dir, "pub.asc")
	exportArmored(t, dir, key.keyID, key.publicASC, "--export")

	return key
}

// TestBootstrapKeys_AreDistinctPerCall pins the premise that roughly fifteen
// tests in this suite rest on: two calls produce two DIFFERENT keys.
//
// Every "an unauthorised signer is denied", "the wrong public key does not
// verify" and "a key in neither block is refused" case gets its second key from
// a second call. If those calls ever returned the same key — and caching them
// is a tempting optimisation, since each runs a full gpg --gen-key or
// ssh-keygen — some of those tests would fail loudly, but others would quietly
// become tautologies: the GPG rotation test would sign with a key that IS the
// allowlisted one and pass while proving nothing.
//
// Cheap to state, and the suite already guards fixture degeneracy this way
// elsewhere (see the re-pushed-candidate test's "fixture is degenerate" check).
func TestBootstrapKeys_AreDistinctPerCall(t *testing.T) {
	t.Parallel()

	requireTool(t, "gpg")
	requireTool(t, "ssh-keygen")

	first, second := bootstrapGPGKey(t), bootstrapGPGKey(t)

	if first.fingerprint == second.fingerprint {
		t.Errorf("two bootstrapGPGKey calls produced the same fingerprint %s — every "+
			"wrong-key and unauthorised-signer test in this suite is now a tautology", first.fingerprint)
	}

	// Separate keyrings too: a shared GNUPGHOME would let one test's key verify
	// another's signature, which is the same failure by a different route.
	if first.gnupgHome == second.gnupgHome {
		t.Errorf("both GPG keys share GNUPGHOME %s; keyrings must be isolated per call", first.gnupgHome)
	}

	firstSSH, secondSSH := bootstrapSSHKey(t), bootstrapSSHKey(t)

	firstPub := strings.TrimSpace(readFile(t, firstSSH.public))
	if firstPub == strings.TrimSpace(readFile(t, secondSSH.public)) {
		t.Error("two bootstrapSSHKey calls produced the same public key — the SSH " +
			"unknown-signer tests cannot distinguish an authorised signer from an unauthorised one")
	}

	// And each allowed_signers authorises its OWN key, not the other's.
	if !strings.Contains(readFile(t, firstSSH.allowedSigners), firstPub) {
		t.Error("allowed_signers does not authorise the key it was generated with")
	}

	if strings.Contains(readFile(t, secondSSH.allowedSigners), firstPub) {
		t.Error("the second allowed_signers authorises the FIRST key; the files are not independent")
	}
}

// exportArmored writes an armored export of keyID to dst, owner-only since
// kind may be --export-secret-keys.
func exportArmored(t *testing.T, gnupgHome, keyID, dst, kind string) {
	t.Helper()

	armored := outputOrFatal(t, toolCommand(t, "", map[string]string{"GNUPGHOME": gnupgHome}, "gpg", "--armor", kind, keyID))
	if armored == "" {
		t.Fatalf("gpg %s %s exported nothing", kind, keyID)
	}

	if err := os.WriteFile(dst, []byte(armored+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// sshKey holds a throwaway ed25519 keypair + an allowed_signers file
// suitable for SSH-format tag signing.
type sshKey struct {
	private        string
	public         string
	allowedSigners string
}

// bootstrapSSHKey generates an ed25519 key + allowed_signers file that
// authorises the same identity used by isolated git commits.
func bootstrapSSHKey(t *testing.T) sshKey {
	t.Helper()
	requireTool(t, "ssh-keygen")

	dir := t.TempDir()
	priv := filepath.Join(dir, "id_ed25519")

	cmd := toolCommand(t, "", nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "integration", "-f", priv)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	pub, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	allowed := filepath.Join(dir, "allowed_signers")
	body := "integration@test.example " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(allowed, []byte(body), 0o600); err != nil {
		t.Fatalf("write allowed_signers: %v", err)
	}

	return sshKey{private: priv, public: priv + ".pub", allowedSigners: allowed}
}

// initGitRepo creates an empty git repo at a fresh dir under t.TempDir
// and runs the supplied configure func against the repo.
//
// All git invocations from this helper go through an isolated config
// stack (GIT_CONFIG_GLOBAL=/dev/null) so the developer's ~/.gitconfig
// — notably gpg.format=ssh — cannot bleed in.
func initGitRepo(t *testing.T, env map[string]string, configure func(repo string, runGit func(args ...string) error)) string {
	t.Helper()
	requireTool(t, "git")

	repo := t.TempDir()

	// isolatedEnv supplies the config isolation and test identity; env only
	// adds what a caller needs on top, such as GNUPGHOME.
	runGit := func(args ...string) error {
		cmd := toolCommand(t, repo, env, "git", args...)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}

		return err
	}

	if err := runGit("init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}

	if configure != nil {
		configure(repo, runGit)
	}

	return repo
}
