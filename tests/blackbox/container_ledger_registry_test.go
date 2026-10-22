// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

package blackbox

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestContainerLedger_PromoteAgainstRegistry exercises the registry-touching
// half of the promotion ladder end to end — `container ledger promote` — but
// daemonless. forge-ci's OCI client is go-containerregistry, so the verb
// resolves digests and moves tags over an in-process registry with NO docker
// daemon and NO outbound network. (The offline add/validate/merge half lives
// in container_ledger_test.go.)
//
// It seeds a throwaway image at the staging candidate tag, records it, runs a
// `--stage dev` promotion, and asserts the moving `:dev` pointer now serves
// the same digest — a verified tag-move done purely over the registry HTTP API.
func TestContainerLedger_PromoteAgainstRegistry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// An in-process OCI registry — pure Go, no daemon. The CLI's ggcr adapter
	// treats loopback registries as insecure (plain HTTP), matching how
	// docker/buildx handle localhost, so no extra wiring is needed.
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	image := srv.Listener.Addr().String() + "/fixture/demo"
	candidate := image + ":staging-v1.2.3"

	// Seed the staging candidate and capture its digest — the value the ledger
	// records and the promotion must preserve.
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

	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	dig := digest.String()

	// Record the entry against the seeded candidate.
	ledger := filepath.Join(t.TempDir(), "release-images.json")
	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "add",
		"--ledger", ledger,
		"--tag", "v1.2.3",
		"--role", "distroless",
		"--ref", image+"@"+dig,
		"--digest", dig,
		"--final-tag", image+":v1.2.3",
		"--candidate-tag", candidate,
	); code != 0 {
		t.Fatalf("ledger add exit=%d stderr=%s", code, stderr)
	}

	// Promote the staging candidate to the :dev moving pointer. Internally this
	// re-verifies the candidate digest, copies the tag, and re-verifies the
	// destination — all via go-containerregistry against the in-process registry.
	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "promote",
		"--ledger", ledger,
		"--tag", "v1.2.3",
		"--stage", "dev",
	); code != 0 {
		t.Fatalf("ledger promote exit=%d stderr=%s", code, stderr)
	}

	// The :dev pointer now serves the promoted candidate's digest.
	got, err := crane.Digest(image+":dev", crane.Insecure, crane.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("resolve :dev digest: %v", err)
	}

	if got != dig {
		t.Errorf(":dev digest = %s, want %s (promoted candidate digest)", got, dig)
	}
}

// TestContainerLedger_PromoteRefusesARepushedCandidate is the negative control
// for the test above, and the reason the ledger records a digest at all: the
// candidate tag is mutable, so between `add` and `promote` someone can push
// different content to it. Promotion must resolve the tag, see a digest that
// is not the recorded one, and refuse — rather than promote whatever the tag
// happens to serve now.
//
// Without this, TestContainerLedger_PromoteAgainstRegistry passes just as well
// against a promote that copies the tag blind: in the happy path the tag still
// serves the recorded digest, so the verification step is invisible.
func TestContainerLedger_PromoteRefusesARepushedCandidate(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	image := srv.Listener.Addr().String() + "/fixture/demo"
	candidate := image + ":staging-v1.2.3"

	candRef, err := name.ParseReference(candidate, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}

	// The image the ledger records.
	recorded, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}

	if err = remote.Write(candRef, recorded, remote.WithContext(ctx)); err != nil {
		t.Fatalf("seed candidate image: %v", err)
	}

	recordedDigest, err := recorded.Digest()
	if err != nil {
		t.Fatal(err)
	}

	dig := recordedDigest.String()

	ledger := filepath.Join(t.TempDir(), "release-images.json")
	if _, stderr, code := run(t, runOpts{},
		"container", "ledger", "add",
		"--ledger", ledger,
		"--tag", "v1.2.3",
		"--role", "distroless",
		"--ref", image+"@"+dig,
		"--digest", dig,
		"--final-tag", image+":v1.2.3",
		"--candidate-tag", candidate,
	); code != 0 {
		t.Fatalf("ledger add exit=%d stderr=%s", code, stderr)
	}

	// Someone re-pushes the candidate tag with different content.
	repushed, err := random.Image(2048, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}

	if err = remote.Write(candRef, repushed, remote.WithContext(ctx)); err != nil {
		t.Fatalf("re-push candidate image: %v", err)
	}

	repushedDigest, err := repushed.Digest()
	if err != nil {
		t.Fatal(err)
	}

	if repushedDigest.String() == dig {
		t.Fatalf("fixture is degenerate: re-pushed image has the recorded digest %s", dig)
	}

	_, stderr, code := run(t, runOpts{},
		"container", "ledger", "promote",
		"--ledger", ledger,
		"--tag", "v1.2.3",
		"--stage", "dev",
	)
	if code == 0 {
		t.Fatalf("promote accepted a re-pushed candidate\nstderr: %s", stderr)
	}

	// The message names the candidate and both digests, so an operator can see
	// that the tag moved rather than guessing at a registry fault.
	assertContains(t, "promote (re-pushed candidate)", stderr, candidate)
	assertContains(t, "promote (re-pushed candidate)", stderr, dig)

	// And nothing was published: the moving pointer must not exist at all.
	if got, err := crane.Digest(image+":dev", crane.Insecure, crane.WithContext(t.Context())); err == nil {
		t.Errorf(":dev was created by a refused promotion and serves %s", got)
	}
}
