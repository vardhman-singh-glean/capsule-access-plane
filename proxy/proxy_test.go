package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// fakeProvider implements providers.CredentialProvider for tests.
type fakeProvider struct {
	name  string
	hosts []string
	token string
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Type() string { return "fake" }
func (p *fakeProvider) Matches(host string) bool {
	for _, h := range p.hosts {
		if h == host {
			return true
		}
	}
	return false
}
func (p *fakeProvider) InjectCredentials(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+p.token)
	return nil
}
func (p *fakeProvider) ResolveToken(_ context.Context) (string, error) {
	return p.token, nil
}
func (p *fakeProvider) Start(_ context.Context) error { return nil }
func (p *fakeProvider) Stop()                         {}

func setupProxy(t *testing.T, targetHost string, allowedIPs []string) (*ConnectProxy, *CertAuthority) {
	t.Helper()

	ca, err := NewCertAuthority()
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}

	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:      "test_api",
		Version:     "1.0",
		SurfaceKind: "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations: []manifest.Destination{
			{Host: targetHost, Port: 443, Protocol: "https", AllowedIPs: allowedIPs},
		},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/allowed/**"},
			{Method: "POST", PathPattern: "/allowed/**"},
		},
	})

	fp := &fakeProvider{name: "test", hosts: []string{targetHost}, token: "test-secret-token"}
	provReg := providers.NewRegistry()
	_ = provReg.Register(fp)

	proxy := &ConnectProxy{
		CA:        ca,
		Manifests: reg,
		Providers: provReg,
		Logger:    slog.Default(),
	}

	return proxy, ca
}

func startProxy(t *testing.T, proxy *ConnectProxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = proxy.Serve(ln) }()
	t.Cleanup(func() { _ = proxy.Close() })
	return ln.Addr().String()
}

func TestCertAuthority_GenerateAndVerify(t *testing.T) {
	ca, err := NewCertAuthority()
	if err != nil {
		t.Fatalf("NewCertAuthority: %v", err)
	}

	cert, err := ca.GetCertificate("api.github.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Second call should return cached cert.
	cert2, err := ca.GetCertificate("api.github.com")
	if err != nil {
		t.Fatalf("GetCertificate (cached): %v", err)
	}
	if cert != cert2 {
		t.Error("expected same pointer for cached cert")
	}
}

func TestProxy_CONNECT_Bump_InjectsCredential(t *testing.T) {
	// Start a TLS target server that echoes the Authorization header.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer target.Close()

	// Parse target host:port.
	targetURL, _ := url.Parse(target.URL)
	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()

	proxy, ca := setupProxy(t, targetHost, []string{"127.0.0.0/8"})

	// Override manifest to allow /** for simplicity.
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:      "test_api",
		Version:     "1.0",
		SurfaceKind: "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations: []manifest.Destination{
			{Host: targetHost, Port: 443, AllowedIPs: []string{"127.0.0.0/8"}},
		},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
		},
	})
	proxy.Manifests = reg

	// Trust the httptest server's self-signed cert for outbound connections.
	proxy.UpstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}

	proxyAddr := startProxy(t, proxy)

	// Make a request through the proxy using CONNECT.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: ca.CACertPool(),
		},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/allowed/test", targetHost, targetPort))
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	// The target sees our injected credential because the proxy MITM'd
	// and called InjectCredentials. However, the target's TLS cert is
	// from httptest (self-signed), so the proxy's outbound transport
	// needs to trust it. Let's check what happened.
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}

	// The Authorization header should be injected by the proxy.
	if string(body) != "Bearer test-secret-token" {
		t.Errorf("body = %q, want 'Bearer test-secret-token'", string(body))
	}
}

func TestProxy_CONNECT_DisallowedHost(t *testing.T) {
	proxy, _ := setupProxy(t, "api.github.com", nil)
	proxyAddr := startProxy(t, proxy)

	// Try to CONNECT to a host not in the manifest.
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufioReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_CONNECT_NonConnect_Rejected(t *testing.T) {
	proxy, _ := setupProxy(t, "api.github.com", nil)
	proxyAddr := startProxy(t, proxy)

	// Send a plain GET (not CONNECT).
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "GET /test HTTP/1.1\r\nHost: api.github.com\r\n\r\n")

	resp, err := http.ReadResponse(bufioReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 405 {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestProxy_CONNECT_Tunnel_NoProvider(t *testing.T) {
	// Start a TLS target server.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tunneled-ok"))
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)
	targetHost := targetURL.Hostname()

	ca, _ := NewCertAuthority()
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "tunnel_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations:   []manifest.Destination{{Host: targetHost, AllowedIPs: []string{"127.0.0.0/8"}}},
	})

	// No provider registered for this host → should tunnel, not bump.
	provReg := providers.NewRegistry()

	proxy := &ConnectProxy{
		CA:                         ca,
		Manifests:                  reg,
		Providers:                  provReg,
		Logger:                     slog.Default(),
		AllowNonProviderPassthrough: true,
	}
	proxyAddr := startProxy(t, proxy)

	// Connect through proxy. Since it tunnels (no MITM), we need to trust
	// the target's TLS cert directly.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			// Trust the httptest server's cert.
			RootCAs: target.TLS.RootCAs,
		},
	}

	// httptest.NewTLSServer uses 127.0.0.1 certs; we need to use that.
	transport.TLSClientConfig.InsecureSkipVerify = true

	client := &http.Client{Transport: transport}
	resp, err := client.Get(target.URL + "/test")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled-ok" {
		t.Errorf("body = %q, want 'tunneled-ok'", string(body))
	}
}

func bufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}
