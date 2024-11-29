// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package caddy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/net/http2"

	caddyscion "github.com/scionproto-contrib/http-proxy/forward/caddy"
)

/*
Test naming: Test{Secure?}Proxy{Method}{Auth}{Policy}
GET/CONNECT -- get gets, connect connects and gets
Auth/NoAuth
Empty/WithPolicy -- tries different credentials
*/
var (
	testResources         = []string{"/", "/image.png"}
	testHTTPProxyVersions = []string{"HTTP/1.1", "HTTP/2.0"}
	// we do not target HTTP2, because the go client does not support
	// using a proxy with HTTP2.
	// https://github.com/golang/go/issues/26479
	testHTTPTargetVersions = []string{"HTTP/1.1"}
	httpVersionToALPN      = map[string]string{
		"HTTP/1.1": "http/1.1",
		"HTTP/2.0": "h2",
	}
)

var (
	credentialsEmpty                = ""
	credentialsIncorrect            = "Basic c3RoOjEyMzQ1"                                         // sth:12345
	credentialsCorrectNoPolicy      = "Basic cG9saWN5Og=="                                         // policy:
	credentialsCorrectPolicyInvalid = "Basic cG9saWN5OmNhZGR5LXNjaW9uLWZvcndhcmQtcHJveHk9Ymx1Yg==" // policy:caddy-scion-forward-proxy=blub
)

var (
	responseEmpty             = []byte("")
	responseOK                = http.StatusOK
	responseProxyAuthRequired = http.StatusProxyAuthRequired
)

func TestSecureProxyGETNoAuth(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsEmpty, useTLS)
			require.NoError(t, err, "GET %s over %s: %v", resource, httpProxyVer, err)
			assert.NoError(t, responseExpected(response, responseProxyAuthRequired, responseEmpty), "GET %s over %s: %v", resource, httpProxyVer, err)
		}
	}
}

func TestSecureProxyGETAuthNoPolicy(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsCorrectNoPolicy, useTLS)
			require.NoError(t, err, "GET %s over %s: %v", resource, httpProxyVer, err)
			assert.NoError(t, responseExpected(response, responseOK, caddyInsecureTestTarget.contents[resource]), "GET %s over %s: %v", resource, httpProxyVer, err)
		}
	}
}

func TestSecureProxyGETIncorrectAuth(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsIncorrect, useTLS)
			require.NoError(t, err, "GET %s over %s: %v", resource, httpProxyVer, err)
			assert.NoError(t, responseExpected(response, responseProxyAuthRequired, responseEmpty), "GET %s over %s: %v", resource, httpProxyVer, err)
		}
	}
}

func TestConnectIncorrectAuth(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpTargetVer, credentialsIncorrect, httpProxyVer, useTLS)
				require.NoError(t, err, "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
				assert.NoError(t, responseExpected(response, responseProxyAuthRequired, responseEmpty), "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
			}
		}
	}
}

// TODO (minor) we should test the policy header more rigorously
func TestGETAuthPolicyInvalid(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsCorrectPolicyInvalid, useTLS)
			require.NoError(t, err, "GET %s over %s: %v", resource, httpProxyVer, err)
			assert.NoError(t, responseExpected(response, responseOK, caddyInsecureTestTarget.contents[resource]), "GET %s over %s: %v", resource, httpProxyVer, err)
		}
	}
}

func TestSecureProxyGETSelf(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddySecureForwardProxy.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsEmpty, useTLS)
			require.NoError(t, err, "GET %s over %s: %v", resource, httpProxyVer, err)
			assert.NoError(t, responseExpected(response, responseOK, caddySecureForwardProxy.contents[resource]), "GET %s over %s: %v", resource, httpProxyVer, err)
		}
	}
}

func TestConnectNoAuth(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpTargetVer, credentialsEmpty, httpProxyVer, useTLS)
				require.NoError(t, err, "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
				assert.NoError(t, responseExpected(response, responseProxyAuthRequired, responseEmpty), "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
			}
		}
	}
}

func TestConnectAuthNoPolicy(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpTargetVer, credentialsCorrectNoPolicy, httpProxyVer, useTLS)
				require.NoError(t, err, "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
				assert.NoError(t, responseExpected(response, responseOK, caddyInsecureTestTarget.contents[resource]), "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
			}
		}
	}
}

func TestConnectAuthPolicyInvalid(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpTargetVer, credentialsCorrectPolicyInvalid, httpProxyVer, useTLS)
				require.NoError(t, err, "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
				assert.NoError(t, responseExpected(response, responseOK, caddyInsecureTestTarget.contents[resource]), "CONNECT %s over %s and %s: %v", resource, httpProxyVer, httpTargetVer, err)
			}
		}
	}
}

func TestAPISetPolicy(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPTargetVersions {
		proxyConn, err := dial(caddySecureForwardProxy.addr, httpProxyVer, useTLS)
		require.NoError(t, err, "Dial proxy over %s: %v", httpProxyVer, err)

		req, err := http.NewRequest(http.MethodPut, "http://"+caddySecureForwardProxy.addr+"/policy", bytes.NewBuffer([]byte(`["+ 42", "-"]`)))
		require.NoError(t, err, "Set Policy over %s: %v", httpProxyVer, err)

		tp := http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			return proxyConn, nil
		}}

		response, err := tp.RoundTrip(req)
		require.NoError(t, err, "Set Policy over %s: %v", httpProxyVer, err)
		assert.NoError(t, responseExpected(response, responseOK, nil), "Set Policy over %s: %v", httpProxyVer, err)
	}
}

func TestAPIGetPath(t *testing.T) {
	// test
}

func TestAPIResolveHost(t *testing.T) {
	// test
}

func TestAPIResolveURL(t *testing.T) {
	// test
}

func BenchmarkSecureProxyGETAuthNoPolicy(b *testing.B) {
	const useTLS = true
	resource := "/"
	httpProxyVer := "HTTP/2.0"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := getViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpProxyVer, credentialsCorrectNoPolicy, useTLS)
		require.NoError(b, err)
	}
}

func BenchmarkConnectAuthNoPolicy(b *testing.B) {
	const useTLS = true
	resource := "/"
	httpTargetVer := "HTTP/1.1"
	httpProxyVer := "HTTP/2.0"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := connectAndGetViaProxy(caddyInsecureTestTarget.addr, resource, caddySecureForwardProxy.addr, httpTargetVer, credentialsCorrectNoPolicy, httpProxyVer, useTLS)
		require.NoError(b, err)
	}
}

func newHttp2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	inErr := h.in.Close()
	outErr := h.out.Close()

	if inErr != nil {
		return inErr
	}
	return outErr
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}

func dial(proxyAddr, httpProxyVer string, useTLS bool) (net.Conn, error) {
	if useTLS {
		return tls.Dial("tcp", proxyAddr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{httpVersionToALPN[httpProxyVer]},
		})
	}
	return net.Dial("tcp", proxyAddr)
}

func getViaProxy(targetHost, resource, proxyAddr, httpProxyVer, proxyCredentials string, useTLS bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, httpProxyVer, useTLS)
	if err != nil {
		return nil, err
	}
	return getResourceViaProxyConn(proxyConn, targetHost, resource, proxyCredentials, httpProxyVer)
}

// if connect is not successful - that response is returned, otherwise the requested resource
func connectAndGetViaProxy(targetHost, resource, proxyAddr, httpTargetVer, proxyCredentials, httpProxyVer string, useTLS bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, httpProxyVer, useTLS)
	if err != nil {
		return nil, err
	}

	req := &http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		req.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	req.Host = targetHost
	req.URL, err = url.Parse("https://" + req.Host + "/") // appending "/" causes file server to NOT issue redirect...
	if err != nil {
		return nil, err
	}
	req.RequestURI = req.Host
	req.Method = "CONNECT"
	req.Proto = httpProxyVer

	var resp *http.Response
	switch httpProxyVer {
	case "HTTP/2.0":
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = io.NopCloser(pr)
		t := http2.Transport{}
		clientConn, err := t.NewClientConn(proxyConn)
		if err != nil {
			return nil, err
		}
		resp, err = clientConn.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		proxyConn = newHttp2Conn(proxyConn, pw, resp.Body)
	case "HTTP/1.1":
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		_ = req.Write(proxyConn) // we don't care about the error here
		resp, err = http.ReadResponse(bufio.NewReader(proxyConn), req)
		if err != nil {
			return resp, err
		}
	default:
		panic("proxy ver: " + httpProxyVer)
	}

	if resp.StatusCode != http.StatusOK {
		return resp, err
	}

	return getResourceViaProxyConn(proxyConn, targetHost, resource, proxyCredentials, httpTargetVer)
}

func getResourceViaProxyConn(proxyConn net.Conn, targetHost, resource, proxyCredentials, httpTargetVer string) (*http.Response, error) {
	var err error

	req := &http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		req.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	req.Host = targetHost
	req.URL, err = url.Parse("http://" + targetHost + resource)
	if err != nil {
		return nil, err
	}
	req.RequestURI = req.Host + resource
	req.Method = "GET"
	req.Proto = httpTargetVer

	switch httpTargetVer {
	case "HTTP/2.0":
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		t := http2.Transport{AllowHTTP: true}
		clientConn, err := t.NewClientConn(proxyConn)
		if err != nil {
			return nil, err
		}
		return clientConn.RoundTrip(req)
	case "HTTP/1.1":
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		t := http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			return proxyConn, nil
		}}
		return t.RoundTrip(req)
	default:
		panic("proxy ver: " + httpTargetVer)
	}
}

// If response is expected: returns nil.
func responseExpected(resp *http.Response, expectedStatusCode int, expectedResponse []byte) error {
	if expectedStatusCode != resp.StatusCode {
		return fmt.Errorf("Expected response status code %d, got %d", expectedStatusCode, resp.StatusCode)
	}

	responseLen := len(expectedResponse) + 2 // 2 extra bytes is enough to detected that expectedResponse is longer
	response := make([]byte, responseLen)
	var nTotal int
	for {
		n, err := resp.Body.Read(response[nTotal:])
		nTotal += n
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		if nTotal == responseLen {
			return fmt.Errorf("nTotal == responseLen, but haven't seen io.EOF. Expected response: '%s'\nGot: '%s'",
				expectedResponse, response)
		}
	}
	response = response[:nTotal]
	if len(expectedResponse) != len(response) {
		return fmt.Errorf("Expected response length: %d, got: %d.\nExpected response: '%s'\nGot: '%s'",
			len(expectedResponse), len(response), expectedResponse, response)
	}
	for i := range response {
		if response[i] != expectedResponse[i] {
			return fmt.Errorf("response mismatch at character #%d. Expected response: '%s'\nGot: '%s'",
				i, expectedResponse, response)
		}
	}
	return nil
}

type caddyTestServer struct {
	addr string
	tls  bool

	root         string // expected to have index.html and image.png
	proxyHandler *caddyscion.Handler
	contents     map[string][]byte
}

var (
	caddySecureForwardProxy   caddyTestServer
	caddyInsecureForwardProxy caddyTestServer

	caddySecureTestTarget   caddyTestServer // serves secure http
	caddyInsecureTestTarget caddyTestServer // serves plain http
)

func (c *caddyTestServer) server() *caddyhttp.Server {
	host, port, err := net.SplitHostPort(c.addr)
	if err != nil {
		panic(err)
	}

	handlerJSON := func(h caddyhttp.MiddlewareHandler) json.RawMessage {
		return caddyconfig.JSONModuleObject(h, "handler", h.(caddy.Module).CaddyModule().ID.Name(), nil)
	}

	// create the routes
	var routes caddyhttp.RouteList
	if c.tls {
		// cheap hack for our tests to get TLS certs for the hostnames that
		// it needs TLS certs for: create an empty route with a single host
		// matcher for that hostname, and auto HTTPS will do the rest
		hostMatcherJSON, err := json.Marshal(caddyhttp.MatchHost{host})
		if err != nil {
			panic(err)
		}
		matchersRaw := caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"host": hostMatcherJSON},
		}
		routes = append(routes, caddyhttp.Route{MatcherSetsRaw: matchersRaw})
	}
	if c.proxyHandler != nil {
		if host != "" {
			// tell the proxy which hostname to serve the proxy on; this must
			// be distinct from the host matcher, since the proxy basically
			// does its own host matching
			c.proxyHandler.Hosts = caddyhttp.MatchHost{host}
		}
		routes = append(routes, caddyhttp.Route{
			HandlersRaw: []json.RawMessage{handlerJSON(c.proxyHandler)},
		})
	}
	if c.root != "" {
		routes = append(routes, caddyhttp.Route{
			HandlersRaw: []json.RawMessage{
				handlerJSON(&fileserver.FileServer{Root: c.root}),
			},
		})
	}

	srv := &caddyhttp.Server{
		Listen: []string{":" + port},
		Routes: routes,
	}
	if c.tls {
		srv.TLSConnPolicies = caddytls.ConnectionPolicies{{}}
	} else {
		srv.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{Disabled: true}
	}

	if c.contents == nil {
		c.contents = make(map[string][]byte)
	}
	index, err := os.ReadFile(c.root + "/index.html")
	if err != nil {
		panic(err)
	}
	c.contents[""] = index
	c.contents["/"] = index
	c.contents["/index.html"] = index
	c.contents["/image.png"], err = os.ReadFile(c.root + "/image.png")
	if err != nil {
		panic(err)
	}

	return srv
}

func TestMain(m *testing.M) {
	// Initialize test proxy servers
	caddySecureForwardProxy = caddyTestServer{
		addr:         "127.0.42.1:8200",
		root:         "./test/forwardproxy",
		tls:          true,
		proxyHandler: &caddyscion.Handler{},
	}

	caddyInsecureForwardProxy = caddyTestServer{
		addr:         "127.0.42.1:8201",
		root:         "./test/forwardproxy",
		proxyHandler: &caddyscion.Handler{},
	}

	// Initialize test target servers
	caddySecureTestTarget = caddyTestServer{
		addr: "127.0.42.2:8300",
		root: "./test/target",
		tls:  true,
	}

	caddyInsecureTestTarget = caddyTestServer{
		addr: "127.0.42.2:8301",
		root: "./test/target",
	}

	// Build the HTTP app
	httpApp := caddyhttp.App{
		HTTPPort: 1080, // Use a high port to avoid permission issues
		Servers: map[string]*caddyhttp.Server{
			"caddySecureForwardProxy":   caddySecureForwardProxy.server(),
			"caddyInsecureForwardProxy": caddyInsecureForwardProxy.server(),
			"caddySecureTestTarget":     caddySecureTestTarget.server(),
			"caddyHTTPTestTarget":       caddyInsecureTestTarget.server(),
		},
		GracePeriod: caddy.Duration(1 * time.Second), // Keep tests fast
	}
	httpAppJSON, err := json.Marshal(httpApp)
	if err != nil {
		panic(err)
	}

	// Ensure we always use internal issuer and not a public CA
	tlsApp := caddytls.TLS{
		Automation: &caddytls.AutomationConfig{
			Policies: []*caddytls.AutomationPolicy{
				{
					IssuersRaw: []json.RawMessage{json.RawMessage(`{"module": "internal"}`)},
				},
			},
		},
	}
	tlsAppJSON, err := json.Marshal(tlsApp)
	if err != nil {
		panic(err)
	}

	// Configure the default CA so that we don't try to install trust, just for our tests
	falseBool := false
	pkiApp := caddypki.PKI{
		CAs: map[string]*caddypki.CA{
			"local": {InstallTrust: &falseBool},
		},
	}
	pkiAppJSON, err := json.Marshal(pkiApp)
	if err != nil {
		panic(err)
	}

	// Build final config
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &falseBool,
			},
		},
		AppsRaw: caddy.ModuleMap{
			"http": httpAppJSON,
			"tls":  tlsAppJSON,
			"pki":  pkiAppJSON,
		},
		Logging: &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {BaseLog: caddy.BaseLog{Level: zap.ErrorLevel.CapitalString()}},
			},
		},
	}

	// Start the Caddy server
	if err := caddy.Run(cfg); err != nil {
		panic(err)
	}

	// Wait for the server to be ready for TLS dial
	time.Sleep(500 * time.Millisecond)

	// Run tests
	retCode := m.Run()

	// Stop the Caddy server
	if err := caddy.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping Caddy server: %v\n", err)
	}

	os.Exit(retCode)
}

// This is a sanity check confirming that target servers actually directly serve what they are expected to.
// (And that they don't serve what they should not)
func TestTheTest(t *testing.T) {
	client := &http.Client{Transport: testTransport, Timeout: 2 * time.Second}

	// Request index
	resp, err := client.Get("http://" + caddyInsecureTestTarget.addr)
	require.NoError(t, err)
	assert.NoError(t, responseExpected(resp, responseOK, caddyInsecureTestTarget.contents[""]))

	// Request image
	resp, err = client.Get("http://" + caddyInsecureTestTarget.addr + "/image.png")
	require.NoError(t, err)
	assert.NoError(t, responseExpected(resp, responseOK, caddyInsecureTestTarget.contents["/image.png"]))

	// Request image, but expect index. Should fail
	resp, err = client.Get("http://" + caddyInsecureTestTarget.addr + "/image.png")
	require.NoError(t, err)
	assert.Error(t, responseExpected(resp, responseOK, caddyInsecureTestTarget.contents[""]))

	// Request index, but expect image. Should fail
	resp, err = client.Get("http://" + caddyInsecureTestTarget.addr)
	require.NoError(t, err)
	assert.Error(t, responseExpected(resp, responseOK, caddyInsecureTestTarget.contents["/image.png"]))

	// Request non-existing resource
	resp, err = client.Get("http://" + caddyInsecureTestTarget.addr + "/idontexist")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Expected: 404 StatusNotFound, got %d. Response: %#v\n", resp.StatusCode, resp)
}

var testTransport = &http.Transport{
	ResponseHeaderTimeout: 2 * time.Second,
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, addr)
	},
	DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return tls.Client(conn, &tls.Config{InsecureSkipVerify: true}), nil
	},
}
