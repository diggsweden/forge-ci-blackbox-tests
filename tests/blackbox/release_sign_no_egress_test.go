// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

//go:build blackbox

// Containment, second half: a signing run configured to publish nothing must
// make no cosign HTTP(S) attempt observable through the configured proxies.
//
// The two are not the same, and the gap is easy to miss. A signing config with
// no transparency-log service stops the Rekor upload — but cosign verifies each
// signature it has just written, and fetches the trust root from
// tuf-repo-cdn.sigstore.dev to do it, once per signature. So "we don't publish"
// left the suite still announcing itself to Sigstore on every signing test.
// --trusted-root closes that.
//
// The proxy below enforces that observable boundary and names the attempted
// HTTP(S) authority. It does not observe other protocols or clients that bypass
// HTTP_PROXY/HTTPS_PROXY.
package blackbox

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// recordEgress starts a loopback HTTP proxy that records routed HTTP requests
// and HTTPS CONNECT attempts and forwards nothing. It returns the proxy URL and
// a func reading back what was recorded.
//
// Go's http.ProxyFromEnvironment (which cosign uses) sends every non-loopback
// request through $HTTPS_PROXY and dials loopback addresses directly. That is
// exactly the split this suite wants: the in-process registry and the Gradle
// daemon stay direct, while cosign's proxy-routed HTTP(S) attempts land here and
// are dropped.
func recordEgress(t *testing.T) (proxyURL string, recorded func() []string) {
	t.Helper()

	var (
		mu       sync.Mutex
		hits     []string
		stopOnce sync.Once
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		hits = append(hits, request.Method+" "+request.Host+" "+request.Proto)
		mu.Unlock()

		response.WriteHeader(http.StatusBadGateway)
	}))

	stop := func() {
		stopOnce.Do(server.Close)
	}
	t.Cleanup(stop)

	return server.URL, func() []string {
		// httptest.Server.Close waits for active handlers. The commands under
		// test complete their proxy request before returning, so the snapshot is
		// deterministic without racing a raw TCP accept backlog.
		stop()

		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), hits...)
	}
}

func TestEgressRecorder_WaitsForAcceptedConnections(t *testing.T) {
	t.Parallel()

	proxy, recorded := recordEgress(t)
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, _ := client.Do(request)
	if response != nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}

	hits := recorded()
	if len(hits) != 1 || hits[0] != "CONNECT example.test:443 HTTP/1.1" {
		t.Fatalf("recorded egress = %v", hits)
	}
}

// signBlobFixture lays out a key and an artifact for one signing run.
func signBlobFixture(t *testing.T) (dir, key string) {
	t.Helper()

	dir = t.TempDir()
	priv, _ := cosignKey(t, dir)

	artifacts := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(artifacts, "app.tgz"), []byte("archive payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir, priv
}

// TestReleaseSign_MakesNoProxyObservableHTTPAttempt verifies that a real
// `release sign --method kms` under transparency=none makes no HTTP(S) attempt
// through the configured proxies.
//
// A file key covers the non-isolated path. `release sign` isolates the cosign
// subprocess environment only for env:// keys (see provenanceSignAllow); that
// isolated environment carries the proxy configuration deliberately, so this
// proxy would see an env:// key's traffic too — see
// TestReleaseSign_EnvKeyMakesNoProxyObservableHTTPAttempt, which covers it.
func TestReleaseSign_MakesNoProxyObservableHTTPAttempt(t *testing.T) {
	requireTool(t, "cosign")

	proxy, recorded := recordEgress(t)
	dir, key := signBlobFixture(t)

	env := proxyEnv(proxy)
	env["COSIGN_PASSWORD"] = ""

	_, stderr, code := run(t, runOpts{dir: dir, env: env}, "release", "sign",
		"--release-artifacts-dir", "release-artifacts",
		"--method", "kms", "--key", key)
	if code != 0 {
		t.Fatalf("release sign exit=%d stderr=%s", code, stderr)
	}

	if hits := recorded(); len(hits) > 0 {
		t.Errorf("release sign made %d proxy-observable HTTP(S) attempt(s) despite publishing nothing: %v\n"+
			"A signing run with the transparency log off must not fetch Sigstore trust material. "+
			"If this is the trust-root fetch, the adapter has stopped passing --trusted-root.",
			len(hits), hits)
	}
}

// TestReleaseSign_EnvKeyMakesNoProxyObservableHTTPAttempt covers the isolated
// signing path, which is the one forgejo-ci actually ships (`--key
// env://COSIGN_KEY`). It builds the cosign adapter through NewIsolated rather
// than New, replacing the subprocess environment wholesale — so "the engine
// resolves the transparency setting" has to hold for a second construction site
// that a reader would not think to check.
//
// This test can see the traffic at all only because the isolated environment
// carries the proxy configuration. It deliberately does not assert that: with
// the transparency log off there is no connection to route, so the proxy
// passthrough is pinned as a unit
// (TestIsolationKeepsTheNetworkConfigurationWhole) where it can actually fail.
func TestReleaseSign_EnvKeyMakesNoProxyObservableHTTPAttempt(t *testing.T) {
	requireTool(t, "cosign")

	proxy, recorded := recordEgress(t)
	dir, key := signBlobFixture(t)

	env := proxyEnv(proxy)
	env["COSIGN_PASSWORD"] = ""
	env["COSIGN_KEY"] = readFile(t, key)

	_, stderr, code := run(t, runOpts{dir: dir, env: env}, "release", "sign",
		"--release-artifacts-dir", "release-artifacts",
		"--method", "kms", "--key", "env://COSIGN_KEY")
	if code != 0 {
		t.Fatalf("release sign with an env:// key exit=%d stderr=%s", code, stderr)
	}

	if hits := recorded(); len(hits) > 0 {
		t.Errorf("isolated signing made %d proxy-observable HTTP(S) attempt(s) despite publishing nothing: %v",
			len(hits), hits)
	}
}

// TestEgressRecorder_CatchesTheTrustRootFetch is the negative control, and the
// reason the test above can be believed: it proves the proxy actually sees what
// it claims to, by making cosign do the very fetch the engine suppresses.
//
// It drives cosign directly with a signing config but NO trusted root — the
// engine's behaviour before --trusted-root was added. cosign then fetches the
// trust root, the proxy records the attempt and drops it.
//
// This is safe to run, which is why it exists where a "does it catch a Rekor
// upload?" control cannot: the suppressed call is a READ of public trust
// material, so even if the proxy were bypassed entirely the worst case is one
// harmless GET — not a permanent public record of an artifact. That asymmetry
// is the whole reason the tlog containment test has no negative control and
// this one does.
func TestEgressRecorder_CatchesTheTrustRootFetch(t *testing.T) {
	requireTool(t, "cosign")

	proxy, recorded := recordEgress(t)
	dir, key := signBlobFixture(t)

	// The engine's own no-transparency-log signing config, inline: this test
	// asserts what happens WITHOUT the matching trusted root, so it cannot go
	// through the engine (which now always pairs them).
	config := filepath.Join(dir, "signing-config.json")
	if err := os.WriteFile(config, []byte(
		`{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json",`+
			`"rekorTlogConfig":{},"tsaConfig":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	env := proxyEnv(proxy)
	env["COSIGN_PASSWORD"] = ""
	env["SIGSTORE_ROOT_FILE"] = "" // This is the no-trusted-root negative control.

	cmd := toolCommand(t, dir, env, "cosign", "sign-blob", "--yes",
		"--key", key,
		"--signing-config", config,
		"--bundle", filepath.Join(dir, "probe.bundle"),
		filepath.Join(dir, "release-artifacts", "app.tgz"))

	_ = cmd.Run() // may fail once the proxy drops the fetch; the attempt is the point

	hits := recorded()
	if len(hits) == 0 {
		t.Fatal("the egress recorder saw nothing when cosign was made to fetch its trust root. " +
			"Either cosign stopped honouring $HTTPS_PROXY or the recorder is broken — " +
			"either way TestReleaseSign_MakesNoProxyObservableHTTPAttempt is now passing vacuously.")
	}

	if !strings.Contains(strings.Join(hits, " "), "sigstore.dev") {
		t.Errorf("expected the recorded attempt to name a sigstore.dev host, got: %v", hits)
	}
}
