// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: EUPL-1.2

//go:build blackbox

package blackbox

// The suite's egress audit. Every binary invocation goes through
// isolatedEnv, and isolatedEnv points the toolchains' proxy knobs at a
// local recording CONNECT proxy — so which hosts a run reached stops
// being something to reason about from lockfiles and becomes something
// the run itself reports.
//
// This is an audit, not a sandbox: a tool that ignores the proxy
// environment bypasses it silently, which is the accepted trade for
// needing no privileges and no vendored dependencies. The fixtures are
// lockfile-only, so a cold cache legitimately resolves from the public
// registries named in egressAllowedHosts; anything else is refused at
// the proxy (the fetching test fails with a named host) and the suite
// exits non-zero listing every violation next to the verdict.
//
// Knobs, both optional:
//   - BLACKBOX_EGRESS_ALLOW: comma-separated extra hosts (exact, or
//     ".suffix.tld" to allow a whole domain) for environments with
//     mirrors or extra toolchains.
//   - BLACKBOX_EGRESS_PROXY=off: skip the audit in the optional local
//     profile while debugging the proxy itself. Strict mode rejects it.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	errEgressAuditDisabled  = errors.New("egress audit disabled by BLACKBOX_EGRESS_PROXY=off") //nolint:gochecknoglobals // sentinel used by strict preflight.
	errEgressProxyNoAddress = errors.New("egress audit proxy has no listening address")        //nolint:gochecknoglobals // sentinel used by strict preflight.
)

// egressBaseAllowedHosts is what the lockfile-only fixtures legitimately
// need on a cold cache, plus where the suite fetches its own inputs.
// A ".suffix" entry allows the domain and every subdomain.
func egressBaseAllowedHosts() []string {
	return []string{
		// Go modules.
		"proxy.golang.org", "sum.golang.org", "storage.googleapis.com",
		// Cargo.
		"crates.io", "static.crates.io", "index.crates.io",
		// Rust toolchain: rustup syncs channel metadata (and, on a cold
		// cache, the toolchain itself) when cargo runs under a pinned
		// rust-toolchain file.
		"static.rust-lang.org",
		// npm.
		"registry.npmjs.org",
		// Node headers for native optional dependencies of cyclonedx-npm.
		"nodejs.org",
		// Maven Central.
		"repo.maven.apache.org", "repo1.maven.org",
		// Gradle distributions + plugin portal, Android SDK/AGP artifacts.
		".gradle.org", "dl.google.com", "maven.google.com",
		// Docker Hub auth, registry, and the blob CDNs a cold pull is
		// redirected to. Both are listed: Docker serves blobs from
		// CloudFront today and from Cloudflare historically, and which one
		// a pull is sent to is Docker's choice, not the caller's.
		"auth.docker.io", "registry-1.docker.io",
		"production.cloudflare.docker.com", "production.cloudfront.docker.com",
		// GitHub, for tool and fixture inputs the suite itself fetches.
		"github.com", "api.github.com", "codeload.github.com",
		"objects.githubusercontent.com", "release-assets.githubusercontent.com",
		"raw.githubusercontent.com",
		// Digest-pinned Android SDK runtime and its image layers.
		"ghcr.io", "pkg-containers.githubusercontent.com",
		// AGP's sources/javadoc publication links these platform API references.
		"developer.android.com", "docs.oracle.com", "kotlinlang.org",
	}
}

func TestEgressBaseAllowedHosts_DockerHubColdPullEndpointsAreExact(t *testing.T) {
	t.Parallel()

	allow := egressBaseAllowedHosts()
	for _, host := range []string{
		"auth.docker.io",
		"registry-1.docker.io",
		"production.cloudflare.docker.com",
		"production.cloudfront.docker.com",
	} {
		if !egressHostAllowedBy(host, allow) {
			t.Errorf("Docker Hub cold-pull endpoint %q is not allowed", host)
		}
	}
	for _, host := range []string{
		"docker.io",
		"evil.auth.docker.io",
		"registry-1.docker.io.attacker.example",
		"unreviewed.cloudflare.docker.com",
		"unreviewed.cloudfront.docker.com",
		"production.cloudfront.docker.com.attacker.example",
	} {
		if egressHostAllowedBy(host, allow) {
			t.Errorf("unreviewed Docker host %q is allowed", host)
		}
	}
}

// TestEgressHostAllowedBy_WildcardEntriesMatchOnADotBoundary covers the
// allowlist's other half. The exact entries are pinned above; the ".suffix.tld"
// form is the security-sensitive one, because it is where a naive matcher lets
// an attacker-controlled parent domain through — and it is the form
// BLACKBOX_EGRESS_ALLOW hands to operators.
//
// Mutation-verified before this existed: weakening the wildcard branch from
// HasSuffix to Contains — which allows "gradle.org.attacker.example" — broke
// nothing in the suite.
func TestEgressHostAllowedBy_WildcardEntriesMatchOnADotBoundary(t *testing.T) {
	t.Parallel()

	allow := []string{".gradle.org", "dl.google.com"}

	for _, host := range []string{
		"gradle.org",          // the bare domain the entry names
		"services.gradle.org", // a subdomain
		"a.b.gradle.org",      // and a deeper one
		"dl.google.com",       // the exact entry still matches itself
	} {
		if !egressHostAllowedBy(host, allow) {
			t.Errorf("host %q should be allowed by %v", host, allow)
		}
	}

	for _, host := range []string{
		"gradle.org.attacker.example",      // allowed text, wrong owner
		"evil.gradle.org.attacker.example", // contains ".gradle.org" but does not end in it
		"notgradle.org",                    // no dot boundary, so a different domain
		"gradle.orgx",
		"evil.dl.google.com", // an exact entry must not imply its subdomains
		"google.com",         // nor its parent
	} {
		if egressHostAllowedBy(host, allow) {
			t.Errorf("host %q must NOT be allowed by %v", host, allow)
		}
	}
}

type egressTally struct {
	mu         sync.Mutex
	seen       map[string]int
	violations map[string]int
}

//nolint:gochecknoglobals // suite-wide audit: the proxy records, TestMain reports.
var egress = struct {
	tally egressTally
	allow []string
}{tally: egressTally{seen: map[string]int{}, violations: map[string]int{}}}

// egressProxy starts the recording proxy on first use and returns its
// host:port, or "" and the reason the audit is not running.
//
//nolint:gochecknoglobals // one proxy per process.
var egressProxy = sync.OnceValues(startEgressProxy)

// egressProxyAddr returns the proxy's host:port, or "" when the audit is off.
func egressProxyAddr() string {
	addr, _ := egressProxy()

	return addr
}

func requireEgressAudit() error {
	return validateEgressAuditStartup(egressProxy())
}

func validateEgressAuditStartup(addr string, startupErr error) error {
	if startupErr != nil {
		return fmt.Errorf("egress audit must run in strict mode: %w", startupErr)
	}
	if addr == "" {
		return fmt.Errorf("egress audit must run in strict mode: %w", errEgressProxyNoAddress)
	}

	return nil
}

func startEgressProxy() (string, error) {
	egress.allow = egressBaseAllowedHosts()

	for _, host := range strings.Split(os.Getenv("BLACKBOX_EGRESS_ALLOW"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			egress.allow = append(egress.allow, host)
		}
	}

	listener, err := openEgressListener(os.Getenv("BLACKBOX_EGRESS_PROXY"), net.Listen)
	if err != nil {
		if !strictProfile() {
			fmt.Fprintf(os.Stderr, "egress audit skipped in optional profile: %v\n", err)
		}

		return "", err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go serveEgressConn(conn)
		}
	}()

	return listener.Addr().String(), nil
}

type egressListenFunc func(network, address string) (net.Listener, error)

func openEgressListener(setting string, listen egressListenFunc) (net.Listener, error) {
	if strings.EqualFold(strings.TrimSpace(setting), "off") {
		return nil, errEgressAuditDisabled
	}

	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start recording proxy: %w", err)
	}

	return listener, nil
}

func TestEgressAuditStartup_DisabledAndListenFailureAreErrors(t *testing.T) {
	t.Parallel()

	called := false
	listener, err := openEgressListener("off", func(_, _ string) (net.Listener, error) {
		called = true

		return nil, errEgressAuditDisabled
	})
	if listener != nil || !errors.Is(err, errEgressAuditDisabled) || called {
		t.Errorf("disabled startup = (%v, %v), listen called=%t", listener, err, called)
	}

	want := os.ErrNotExist
	listener, err = openEgressListener("", func(_, _ string) (net.Listener, error) {
		return nil, want
	})
	if listener != nil || !errors.Is(err, want) {
		t.Errorf("failed startup = (%v, %v), want wrapped %v", listener, err, want)
	}
	if strictErr := validateEgressAuditStartup("", err); !errors.Is(strictErr, want) {
		t.Errorf("strict startup failure = %v, want wrapped %v", strictErr, want)
	}
	if strictErr := validateEgressAuditStartup("127.0.0.1:1234", nil); strictErr != nil {
		t.Errorf("strict listening proxy rejected: %v", strictErr)
	}
}

// serveEgressConn handles one proxied connection: a CONNECT tunnel for
// TLS, or a single absolute-URI plain-HTTP request.
func serveEgressConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	// An idle client must not pin this goroutine for the rest of the run.
	if deadlineErr := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); deadlineErr != nil {
		return
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	hostPort := req.Host
	if req.Method != http.MethodConnect && req.URL != nil && req.URL.Host != "" {
		hostPort = req.URL.Host
	}

	host := hostPort
	if h, _, splitErr := net.SplitHostPort(hostPort); splitErr == nil {
		host = h
	}

	if !auditEgressHost(host) {
		// Refused loudly: the fetching test fails naming the host, and
		// the suite verdict lists it again.
		refuseProxyRequest(conn, http.StatusForbidden, fmt.Sprintf("egress to %q is not in the suite allowlist\n", host))

		return
	}

	upstreamAddr := hostPort
	if _, _, splitErr := net.SplitHostPort(upstreamAddr); splitErr != nil {
		upstreamAddr = net.JoinHostPort(upstreamAddr, "80")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		refuseProxyRequest(conn, http.StatusBadGateway, err.Error()+"\n")

		return
	}

	defer func() { _ = upstream.Close() }()

	// Only the request read is bounded; a tunnel may idle legitimately.
	if deadlineErr := conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
		return
	}

	if req.Method != http.MethodConnect {
		// One audited request per connection. A reused connection would carry
		// later requests to this upstream without passing the allowlist.
		req.Close = true
		if writeErr := req.WriteProxy(upstream); writeErr == nil {
			_, _ = io.Copy(conn, upstream)
		}

		return
	}

	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	done := make(chan struct{}, 2)

	// Copy from reader, not conn: bytes the client pipelined behind the
	// request (a TLS ClientHello sent optimistically after CONNECT) are
	// already buffered in reader and would otherwise be lost.
	go func() { _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

// refuseProxyRequest answers the client with status and a plain-text reason.
// The caller closes the connection, which the response announces.
func refuseProxyRequest(conn net.Conn, status int, reason string) {
	response := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         true,
		ContentLength: int64(len(reason)),
		Body:          io.NopCloser(strings.NewReader(reason)),
	}

	_ = response.Write(conn)
}

// auditEgressHost tallies host and reports whether it is allowed. (The
// per-test recordEgress in release_sign_no_egress_test.go is its sibling:
// that one drops everything to prove zero egress; this one forwards
// through the allowlist to audit legitimate egress.)
func auditEgressHost(host string) bool {
	allowed := egressHostAllowed(host)

	egress.tally.mu.Lock()
	defer egress.tally.mu.Unlock()

	if allowed {
		egress.tally.seen[host]++
	} else {
		egress.tally.violations[host]++
	}

	return allowed
}

func egressHostAllowed(host string) bool {
	return egressHostAllowedBy(host, egress.allow)
}

func egressHostAllowedBy(host string, allowedHosts []string) bool {
	for _, allow := range allowedHosts {
		if strings.HasPrefix(allow, ".") {
			if strings.HasSuffix(host, allow) || host == strings.TrimPrefix(allow, ".") {
				return true
			}
		} else if host == allow {
			return true
		}
	}

	return false
}

// egressProxyEnv returns the environment entries that route one binary
// invocation through the audit, or nil when the audit is off. Loopback
// destinations bypass the proxy: local fixtures are not egress.
func egressProxyEnv() map[string]string {
	addr := egressProxyAddr()
	if addr == "" {
		return nil
	}

	return proxyEnv("http://" + addr)
}

// proxyEnv routes a process through proxyURL under every spelling tools
// read, so no lowercase or ALL_PROXY value from elsewhere wins. Loopback
// destinations bypass it. The map is fresh, so callers may add to it.
func proxyEnv(proxyURL string) map[string]string {
	return map[string]string{
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"ALL_PROXY":   proxyURL,
		"NO_PROXY":    "127.0.0.1,localhost,::1",
		"no_proxy":    "127.0.0.1,localhost,::1",
	}
}

// egressJVMProxyOpts returns the -D properties the JVM needs to honour
// the same proxy: Java ignores the proxy environment variables.
func egressJVMProxyOpts() string {
	addr := egressProxyAddr()
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}

	return fmt.Sprintf(
		" -Dhttp.proxyHost=%[1]s -Dhttp.proxyPort=%[2]s -Dhttps.proxyHost=%[1]s -Dhttps.proxyPort=%[2]s -Dhttp.nonProxyHosts=localhost|127.0.0.1",
		host, port)
}

// reportEgress publishes the audit next to the verdict, mirroring
// reportMissingTools: stderr for a human, GITHUB_STEP_SUMMARY for CI.
// Returns the number of violating hosts so TestMain can fail the run.
func reportEgress(out io.Writer) int {
	egress.tally.mu.Lock()
	defer egress.tally.mu.Unlock()

	if len(egress.tally.violations) == 0 {
		return 0
	}

	hosts := slices.Sorted(maps.Keys(egress.tally.violations))

	var report strings.Builder

	fmt.Fprintf(&report, "%d host(s) outside the egress allowlist were refused:\n", len(hosts))

	for _, host := range hosts {
		fmt.Fprintf(&report, "  %-40s %d attempt(s)\n", host, egress.tally.violations[host])
	}

	report.WriteString("Add legitimate hosts via BLACKBOX_EGRESS_ALLOW or egressBaseAllowedHosts.\n")

	_, _ = fmt.Fprintf(out, "\nEGRESS VIOLATIONS: %s", report.String())

	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		if err := appendStepSummary(summary, "Egress violations", report.String()); err != nil {
			_, _ = fmt.Fprintf(out, "cannot write GITHUB_STEP_SUMMARY: %v\n", err)
		}
	}

	return len(hosts)
}
