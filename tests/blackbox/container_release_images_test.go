// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// `container release-images` is the workflow-facing orchestration boundary
// that Forge CI's sign-and-publish-release.yml gates its releases on
// (release-images sign / promote / rollback / cleanup). It wraps the
// digest-first ledger with short-lived registry auth and a rollback journal.
//
// The primitive layer underneath it is covered by container_ledger_test.go
// (offline) and container_ledger_registry_test.go (registry-touching). This
// file covers the boundary itself, daemonless: an in-process OCI registry, no
// docker, no outbound network.
//
// Deliberately NOT covered here, so the gaps are visible rather than implied:
//
//   - `release-images sign` and `release-images validate` — both need a Cosign
//     keypair and an image carrying real signature/CycloneDX/SLSA attestations,
//     not a seeded random one.
//   - successful package-API deletion — the credential test reaches a refusing
//     loopback API. The refusal and journal-planning paths are covered, but a
//     real forge's tag-deletion effects are not.
//   - `container base-images` — the other half of the orchestration boundary
//     (Forge CI's promote/verify-base-container-images.yml).

package blackbox

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// releaseImagesFixture is one seeded release candidate plus the ledger that
// records it, laid out the way the release-images commands expect: the ledger
// lives under dist/, the journal under a separate state dir.
type releaseImagesFixture struct {
	host      string // registry host:port, no scheme
	image     string // <host>/<owner>/<repo>
	candidate string // <image>:staging-<tag>
	digest    string // sha256:… of the seeded candidate
	distDir   string
	ledger    string
	journal   string
}

// seedReleaseImages starts an in-process registry, pushes a throwaway image at
// the staging candidate tag, and records it in a ledger via `ledger add`.
func seedReleaseImages(t *testing.T, tag string) releaseImagesFixture {
	t.Helper()

	return seedReleaseImagesWithAPI(t, tag, nil)
}

func seedReleaseImagesWithAPI(t *testing.T, tag string, packageAPI http.Handler) releaseImagesFixture {
	t.Helper()

	ctx := t.Context()

	images := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if packageAPI != nil && strings.HasPrefix(r.URL.Path, "/api/v1/") {
			packageAPI.ServeHTTP(w, r)

			return
		}
		images.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	host := srv.Listener.Addr().String()
	image := host + "/fixture/demo"
	candidate := image + ":staging-" + tag

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}

	candRef, err := name.ParseReference(candidate, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}

	if err = remote.Write(candRef, img, remote.WithContext(ctx)); err != nil {
		t.Fatalf("seed candidate image: %v", err)
	}

	var digest v1.Hash

	digest, err = img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	dig := digest.String()

	// The ledger must live under --dist-dir; the journal is state, not dist.
	distDir := t.TempDir()
	fix := releaseImagesFixture{
		host:      host,
		image:     image,
		candidate: candidate,
		digest:    dig,
		distDir:   distDir,
		ledger:    filepath.Join(distDir, "release-images.json"),
		journal:   filepath.Join(t.TempDir(), "image-promotions.jsonl"),
	}

	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "add",
		"--ledger", fix.ledger,
		"--tag", tag,
		"--role", "distroless",
		"--ref", image+"@"+dig,
		"--digest", dig,
		"--final-tag", image+":"+tag,
		"--moving-tag", image+":stable",
		"--candidate-tag", candidate,
	); code != 0 {
		t.Fatalf("ledger add exit=%d stderr=%s", code, stderr)
	}

	return fix
}

// runReleaseImages invokes a release-images subcommand with the registry
// credentials the boundary requires. The password arrives via the environment,
// never argv — that is the command's own contract (--registry-password-file or
// $REGISTRY_TOKEN), and honouring it here keeps the token out of process args.
//
// expectedRepo becomes --expected-image-repository; "" omits the flag, which
// the boundary rejects (see TestReleaseImagesPromote_RequiresRepositoryScope).
func runReleaseImages(t *testing.T, fix releaseImagesFixture, tag, expectedRepo, sub string, extra ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	args := []string{
		"container", "release-images", sub,
		"--dist-dir", fix.distDir,
		"--ledger", fix.ledger,
		"--tag", tag,
		"--stage", "release",
		"--registry", fix.host,
		"--registry-username", "tester",
		"--journal", fix.journal,
	}

	if expectedRepo != "" {
		args = append(args, "--expected-image-repository", expectedRepo)
	}

	args = append(args, extra...)

	return run(t, runOpts{env: map[string]string{"REGISTRY_TOKEN": "test-token"}}, args...)
}

// TestReleaseImagesPromote_RequiresRepositoryScope pins the boundary's
// fail-closed entry condition: an operator must state which repository the
// ledger may touch, either explicitly (--expected-image-repository) or via the
// forge context (--server-url + --repository). Promotion moves release tags
// using refs read out of a file; without a declared scope there is nothing to
// check those refs against, so the command refuses to start rather than trust
// the ledger.
func TestReleaseImagesPromote_RequiresRepositoryScope(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	_, stderr, code := runReleaseImages(t, fix, "v1.2.3", "", "promote")
	if code != exitUsage {
		t.Fatalf("promote without a repository scope: exit=%d, want 2 (usage); stderr=%s", code, stderr)
	}

	assertContains(t, "names the missing scope flags", stderr, "--expected-image-repository")
}

// TestReleaseImagesPromote_LandsTheLedgerReleaseTags is the happy path of the
// boundary Forge CI calls.
//
// Note what "release" means here: unlike a named `ledger promote --stage dev`,
// which adds a generic <base>:<stage> pointer, release promotion sets
// UseEntryReleaseTags and copies the candidate to the exact destinations the
// ledger entry carries — final_tag and the optional moving_tag. There is
// deliberately no <base>:release pointer. That is the build-once,
// sign-before-publish model: the immutable final tag is not applied until after
// signing, so the tag appearing IS the signal that the release was signed.
func TestReleaseImagesPromote_LandsTheLedgerReleaseTags(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("release-images promote exit=%d stderr=%s", code, stderr)
	}

	// The immutable final tag now serves the candidate's digest: same bytes,
	// promoted rather than rebuilt.
	got, err := crane.Digest(fix.image+":v1.2.3", crane.Insecure, crane.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("resolve final tag :v1.2.3: %v", err)
	}

	if got != fix.digest {
		t.Errorf(":v1.2.3 digest = %s, want %s (promoted candidate)", got, fix.digest)
	}

	// The entry's moving tag lands on the same digest in the same promotion.
	got, err = crane.Digest(fix.image+":stable", crane.Insecure, crane.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("resolve moving tag :stable: %v", err)
	}

	if got != fix.digest {
		t.Errorf(":stable digest = %s, want %s (promoted candidate)", got, fix.digest)
	}
}

// TestReleaseImagesPromote_WritesTheRollbackJournal pins that a successful
// promotion leaves a journal recording the promoted digest.
//
// The stronger crash-safety claim — journal written BEFORE the first tag
// moves — is not provable from this side of the boundary: failing the copy
// step from outside (deleting the candidate manifest) also fails journal
// planning, because both resolve the same digest. The ordering is pinned in
// the engine instead, where the copy can fail alone:
// forge-ci internal/cli/commands/container
// TestRunLedgerPromotion_JournalsBeforeTheFirstCopy.
func TestReleaseImagesPromote_WritesTheRollbackJournal(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("release-images promote exit=%d stderr=%s", code, stderr)
	}

	if !fileExists(fix.journal) {
		t.Fatalf("no promotion journal at %s — a failed promotion could not be rolled back", fix.journal)
	}

	body := readFile(t, fix.journal)
	assertContains(t, "journal records the promoted digest", body, fix.digest)
}

// TestReleaseImagesPromote_DryRunMutatesNothing pins --dry-run as a genuine
// preview. An operator reaching for it before a real release must not move a
// single tag.
func TestReleaseImagesPromote_DryRunMutatesNothing(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote", "--dry-run"); code != 0 {
		t.Fatalf("release-images promote --dry-run exit=%d stderr=%s", code, stderr)
	}

	if _, err := crane.Digest(fix.image+":v1.2.3", crane.Insecure, crane.WithContext(t.Context())); err == nil {
		t.Errorf("final tag :v1.2.3 exists after --dry-run — the preview mutated the registry")
	}

	if _, err := crane.Digest(fix.image+":stable", crane.Insecure, crane.WithContext(t.Context())); err == nil {
		t.Errorf("moving tag :stable exists after --dry-run — the preview mutated the registry")
	}

	// A preview must not write rollback state for mutations it did not perform.
	if fileExists(fix.journal) {
		t.Errorf("--dry-run wrote the promotion journal %s:\n%s\na later rollback would undo a promotion that never happened",
			fix.journal, readFile(t, fix.journal))
	}
}

// TestReleaseImagesPromote_RejectsForeignRepository pins the signer/publisher
// trust boundary (ADR 0002): --expected-image-repository is the operator's
// statement of which repository the ledger is allowed to touch. A ledger entry
// pointing somewhere else must fail closed, before any tag moves — otherwise a
// poisoned ledger could redirect a signed promotion at an attacker's repo.
func TestReleaseImagesPromote_RejectsForeignRepository(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	_, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.host+"/someone-else/evil", "promote")
	if code != exitValidation {
		t.Fatalf("promote outside --expected-image-repository: exit=%d, want 1 (EX_VALIDATION); stderr=%s", code, stderr)
	}

	// The message names the scope rule and the ref it rejected. Accepting any
	// non-zero exit would let an unrelated failure — a registry that never
	// answered, say — stand in for the check this test exists to prove.
	assertContains(t, "names the repository scope rule", stderr, "ref must be under "+fix.host+"/someone-else/evil")

	// Fail closed means fail BEFORE mutating: no release tag may exist.
	if _, err := crane.Digest(fix.image+":v1.2.3", crane.Insecure, crane.WithContext(t.Context())); err == nil {
		t.Errorf("final tag :v1.2.3 was created despite the repository check failing")
	}
}

// TestReleaseImagesRollback_RequiresAProviderToken pins rollback's fail-closed
// entry condition.
//
// Undoing a promotion means DELETING tags the promotion created, which happens
// through the forge's package API rather than the registry — one of the
// Forgejo-specific concerns this boundary bundles on top of the ledger. Deletion
// authority is therefore explicit: no token, no attempt. A rollback that
// silently degraded to "delete what I can" would leave a half-undone release,
// which is the state the journal exists to prevent.
//
// The tags promote created must survive the refusal: failing closed here means
// changing nothing, so a rollback with the right token can still undo it.
func TestReleaseImagesRollback_RequiresAProviderToken(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("release-images promote exit=%d stderr=%s", code, stderr)
	}

	_, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "rollback")
	if code != exitUsage {
		t.Fatalf("rollback without a provider token: exit=%d, want 2 (usage); stderr=%s", code, stderr)
	}

	assertContains(t, "names the token flag", stderr, "--provider-token-file")

	// Refusing must be inert: the promoted tag is still there to undo later.
	got, err := crane.Digest(fix.image+":v1.2.3", crane.Insecure, crane.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("refused rollback destroyed the promoted tag: %v", err)
	}

	if got != fix.digest {
		t.Errorf(":v1.2.3 digest = %s, want %s (a refusal must change nothing)", got, fix.digest)
	}
}

// The executing path must read the package-API credential, prefer it over the
// native fallback, and keep it separate from registry auth. A dry run bypasses
// that read entirely, so it cannot establish this contract.
func TestReleaseImagesRollback_AuthenticatesPackageAPI(t *testing.T) {
	t.Parallel()

	requests := make(chan string, 2)
	fix := seedReleaseImagesWithAPI(t, "v1.2.3", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- r.Method + " " + r.URL.Path + " | " + r.Header.Get("Authorization"):
		default:
			t.Error("unexpected repeated package-API request")
		}

		http.Error(w, "fixture denies deletion", http.StatusForbidden)
	}))
	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("release-images promote exit=%d stderr=%s", code, stderr)
	}

	stdout, stderr, code := run(t, runOpts{env: map[string]string{
		"FORGE_CI_PROVIDER":          "forgejo",
		"FORGE_CI_PACKAGE_API_TOKEN": "package-api-fixture",
		"FORGEJO_TOKEN":              "native-fallback-fixture",
		"REGISTRY_TOKEN":             "registry-fixture",
	}},
		"container", "release-images", "rollback",
		"--dist-dir", fix.distDir, "--ledger", fix.ledger, "--journal", fix.journal,
		"--tag", "v1.2.3", "--stage", "release", "--registry", fix.host,
		"--registry-username", "tester", "--expected-image-repository", fix.image,
		"--server-url", "http://"+fix.host, "--repository", "fixture/demo",
	)
	if code != exitNoPerm {
		t.Fatalf("rollback with a refusing package API: exit=%d, want %d; stderr=%s", code, exitNoPerm, stderr)
	}

	select {
	case got := <-requests:
		const want = "DELETE /api/v1/packages/fixture/container/demo/stable | token package-api-fixture"
		if got != want {
			t.Errorf("package-API request = %q, want %q", got, want)
		}
	default:
		t.Fatal("rollback never reached the package API")
	}

	for _, token := range []string{"package-api-fixture", "native-fallback-fixture", "registry-fixture"} {
		if strings.Contains(stdout+stderr, token) {
			t.Error("rollback exposed a credential in its output")
		}
	}
}

func TestReleaseImagesRollbackRefusesForeignPackageAPI(t *testing.T) {
	t.Parallel()
	fix := seedReleaseImages(t, "v1.2.3")
	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("promote exit=%d: %s", code, stderr)
	}
	requests := make(chan struct{}, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requests <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(api.Close)
	_, stderr, code := run(t, runOpts{env: map[string]string{
		"FORGE_CI_PROVIDER": "forgejo", "FORGE_CI_PACKAGE_API_TOKEN": "package-api-fixture", "REGISTRY_TOKEN": "registry-fixture",
	}}, "container", "release-images", "rollback", "--dist-dir", fix.distDir,
		"--ledger", fix.ledger, "--journal", fix.journal, "--tag", "v1.2.3", "--stage", "release",
		"--registry", fix.host, "--registry-username", "tester", "--expected-image-repository", fix.image,
		"--server-url", api.URL, "--repository", "fixture/demo")
	if code != exitUsage || !strings.Contains(stderr, "the image is not in the registry") {
		t.Fatalf("foreign package API exit=%d, want authority refusal: %s", code, stderr)
	}
	select {
	case <-requests:
		t.Fatal("foreign package API received deletion authority")
	default:
	}
	if got, err := crane.Digest(fix.image+":stable", crane.Insecure, crane.WithContext(t.Context())); err != nil || got != fix.digest {
		t.Fatalf("foreign API refusal changed the promoted image: %q: %v", got, err)
	}
}

// TestReleaseImagesRollback_DryRunPlansFromTheJournal covers the journal-reading
// half of rollback without a forge: --dry-run previews the deletions it would
// issue, so the journal promote wrote must be parseable and name the promoted
// tag. The deletions themselves go through the package API and are not
// reachable from an in-process registry, so the executing half stays uncovered
// here (see the file header).
func TestReleaseImagesRollback_DryRunPlansFromTheJournal(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	if _, stderr, code := runReleaseImages(t, fix, "v1.2.3", fix.image, "promote"); code != 0 {
		t.Fatalf("release-images promote exit=%d stderr=%s", code, stderr)
	}

	stdout, stderr, code := run(t, runOpts{env: map[string]string{
		"REGISTRY_TOKEN": "test-token",
	}},
		"container", "release-images", "rollback",
		"--dist-dir", fix.distDir,
		"--ledger", fix.ledger,
		"--tag", "v1.2.3",
		"--stage", "release",
		"--registry", fix.host,
		"--registry-username", "tester",
		"--journal", fix.journal,
		"--expected-image-repository", fix.image,
		"--dry-run",
	)
	if code != 0 {
		t.Fatalf("rollback --dry-run exit=%d stderr=%s", code, stderr)
	}

	assertContains(t, "dry-run names the tag it would remove", stdout+stderr, "[dry-run] would delete "+fix.image+":v1.2.3")

	// A preview must not delete: the promoted tag survives.
	if _, err := crane.Digest(fix.image+":v1.2.3", crane.Insecure, crane.WithContext(t.Context())); err != nil {
		t.Errorf("rollback --dry-run removed the promoted tag: %v", err)
	}
}

// TestReleaseImagesRollback_SaysWhyThereIsNothingToRollBack pins the difference
// between the two "nothing to undo" states.
//
// Both are legitimate — a workflow's `if: failure()` rollback step runs even
// when the promotion failed before journalling — so neither is an error. But a
// missing journal is also exactly what a mistyped --journal path, or a state
// dir that did not survive between CI jobs, looks like. An operator who reads
// a bare "nothing to roll back" there concludes the release was undone when it
// was not, so the message has to name which state it found.
func TestReleaseImagesRollback_SaysWhyThereIsNothingToRollBack(t *testing.T) {
	t.Parallel()

	fix := seedReleaseImages(t, "v1.2.3")

	rollback := func() (stderr string, code int) {
		t.Helper()

		_, stderr, code = run(t, runOpts{env: map[string]string{
			"REGISTRY_TOKEN": "test-token",
		}},
			"container", "release-images", "rollback",
			"--dist-dir", fix.distDir,
			"--ledger", fix.ledger,
			"--tag", "v1.2.3",
			"--stage", "release",
			"--registry", fix.host,
			"--registry-username", "tester",
			"--journal", fix.journal,
			"--expected-image-repository", fix.image,
			"--dry-run",
		)

		return stderr, code
	}

	// No journal at all: the promotion never journalled, or --journal points
	// somewhere the promotion did not write.
	stderr, code := rollback()
	if code != 0 {
		t.Fatalf("rollback with no journal exit=%d, want 0 (nothing to undo is not an error)\nstderr: %s", code, stderr)
	}

	assertContains(t, "rollback (no journal)", stderr, "No promotion journal at")
	assertContains(t, "rollback (no journal)", stderr, fix.journal)

	// Journal present but empty: promote ran and recorded nothing.
	if err := os.WriteFile(fix.journal, nil, 0o644); err != nil {
		t.Fatalf("create empty journal: %v", err)
	}

	stderr, code = rollback()
	if code != 0 {
		t.Fatalf("rollback with an empty journal exit=%d, want 0\nstderr: %s", code, stderr)
	}

	assertContains(t, "rollback (empty journal)", stderr, "is empty")

	// The two states must remain distinguishable.
	if strings.Contains(stderr, "No promotion journal at") {
		t.Error("an empty journal reports as a missing one; the two states are indistinguishable again")
	}
}
