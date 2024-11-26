// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build e2e

package test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/pkg/daemon"
	"go.uber.org/zap"

	caddyscion "github.com/scionassociation/http-scion/forward/caddy"
	_ "github.com/scionassociation/http-scion/reverse"
)

var (
	sciondAddr = flag.String("sciond-address", "127.0.0.1:30255", "address to the scion daemon")

	targetServerResponseBody = []byte("hello from test server")
)

const (
	ipHost    = "localhost"
	scionHost = "scion.local"

	forwardProxyHost = "localhost"
	forwardProxyPort = 1443

	reverseProxyHTTPPort  = 2080
	reverseProxyHTTPsPort = 2443

	targetServerHost               = "localhost"
	targetServerPort               = 3080
	targetServerResponseStatusCode = http.StatusOK

	emptyPolicy = ""
)

func TestGetTargetViaProxy(t *testing.T) {
	tests := []struct {
		name         string
		proxyUseTLS  bool
		targetUseTLS bool
		targetHost   string
		targetPort   int
	}{
		{"HTTPsTargetViaHTTPsProxyOverSCION", true, true, scionHost, reverseProxyHTTPsPort},
		{"HTTPsTargetViaHTTPsProxyOverIP", true, true, ipHost, reverseProxyHTTPsPort},
		{"HTTPTargetViaHTTPsProxyOverSCION", true, false, scionHost, reverseProxyHTTPPort},
		{"HTTPTargetViaHTTPsProxyOverIP", true, false, ipHost, reverseProxyHTTPPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := getViaProxy(forwardProxyHost, forwardProxyPort, tt.proxyUseTLS, tt.targetHost, tt.targetPort, tt.targetUseTLS)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGetTargetOverIP(t *testing.T) {
	tests := []struct {
		name   string
		useTLS bool
	}{
		{"HTTPsTargetOverIP", true},
		{"HTTPTargetOverIP", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testGetTargetOverIP(t, tt.useTLS)
		})
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	err := checkScionConfiguration(*sciondAddr)
	if err != nil {
		panic(err)
	}

	handlerJSON := func(h caddyhttp.MiddlewareHandler) json.RawMessage {
		return caddyconfig.JSONModuleObject(h, "handler", h.(caddy.Module).CaddyModule().ID.Name(), nil)
	}

	hostJSON, err := json.Marshal([]string{ipHost, scionHost})
	if err != nil {
		panic(err)
	}

	httpApp := caddyhttp.App{
		HTTPPort:  reverseProxyHTTPPort,
		HTTPSPort: reverseProxyHTTPsPort,
		Servers: map[string]*caddyhttp.Server{
			"forward": {
				Listen: []string{fmt.Sprintf(":%d", forwardProxyPort)},
				Routes: caddyhttp.RouteList{
					caddyhttp.Route{
						HandlersRaw: []json.RawMessage{handlerJSON(&caddyscion.Handler{})},
					},
				},
				TLSConnPolicies: []*caddytls.ConnectionPolicy{
					{}, // empty connection policy trigger TLS on all listeners (except HTTPPort)
				},
			},
			"reverse": {
				Listen: []string{
					fmt.Sprintf(":%d", reverseProxyHTTPPort),
					fmt.Sprintf(":%d", reverseProxyHTTPsPort),
					fmt.Sprintf("scion/:%d", reverseProxyHTTPPort),
					fmt.Sprintf("scion/:%d", reverseProxyHTTPsPort),
				},
				Routes: caddyhttp.RouteList{
					caddyhttp.Route{
						MatcherSetsRaw: caddyhttp.RawMatcherSets{
							caddy.ModuleMap{"host": json.RawMessage(hostJSON)},
						},
						HandlersRaw: []json.RawMessage{handlerJSON(&reverseproxy.Handler{
							Upstreams: reverseproxy.UpstreamPool{
								&reverseproxy.Upstream{
									Dial: fmt.Sprintf("%s:%d", targetServerHost, targetServerPort),
								},
							},
						})},
					},
				},
				// We disable HTTP/3 over IP for the reverse proxy server because it will clash with the scion listener
				// In any case we are not using HTTP/3 in this test.
				Protocols: []string{"h1", "h2"},
			},
			"dummy": {
				Listen: []string{fmt.Sprintf(":%d", targetServerPort)},
				Routes: caddyhttp.RouteList{
					caddyhttp.Route{
						HandlersRaw: []json.RawMessage{handlerJSON(&caddyhttp.StaticResponse{
							StatusCode: caddyhttp.WeakString(fmt.Sprintf("%d", targetServerResponseStatusCode)),
							Body:       string(targetServerResponseBody),
						})},
					},
				},
			},
		},
		GracePeriod: caddy.Duration(1 * time.Second), // keep tests fast
	}
	httpAppJSON, err := json.Marshal(httpApp)
	if err != nil {
		panic(err)
	}

	// ensure we always use internal issuer and not a public CA and issue certificate for forward proxy host
	tlsApp := caddytls.TLS{
		CertificatesRaw: caddy.ModuleMap{"automate": json.RawMessage(fmt.Sprintf(`["%s"]`, forwardProxyHost))},
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

	// configure the default CA so that we don't try to install trust, just for our tests
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

	// build final config
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
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
			},
		},
	}

	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(cfgJSON))

	// start the engines
	err = caddy.Run(cfg)
	if err != nil {
		panic(err)
	}

	// wait server ready for tls dial
	time.Sleep(500 * time.Millisecond)

	retCode := m.Run()

	caddy.Stop() // ignore error on shutdown

	os.Exit(retCode)
}

func testGetTargetOverIP(t *testing.T, useTLS bool) {
	scheme := "http"
	port := reverseProxyHTTPPort
	if useTLS {
		scheme = "https"
		port = reverseProxyHTTPsPort
	}

	client := &http.Client{
		Transport: &http.Transport{
			// We need to skip verification because the certificate from the Caddy endpoint is self-signed
			// and the Go client will not have the CA to verify it.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, ipHost, port)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to get target over IP: %v", err)
	}
	defer resp.Body.Close()

	if err := responseExpected(resp, targetServerResponseStatusCode, targetServerResponseBody); err != nil {
		t.Fatalf("Unexpected response: %v", err)
	}
}

func getViaProxy(proxyHost string, proxyPort int, proxyUseTLS bool, targetHost string, targetPort int, targetUseTLS bool) error {
	proxyScheme := "http"
	if proxyUseTLS {
		proxyScheme = "https"
	}

	targetScheme := "http"
	if targetUseTLS {
		targetScheme = "https"
	}

	proxyURL := &url.URL{
		Scheme: proxyScheme,
		Host:   fmt.Sprintf("%s:%d", proxyHost, proxyPort),
		User:   url.UserPassword("policy", emptyPolicy),
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// We need to skip verification because the certificate from the Caddy forward proxy is self-signed
		// and the Go client will not have the CA to verify it.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// the go http client does not support http2 proxy, only http1 proxies
		// see: https://github.com/golang/go/issues/26479
		// we would need to create both connection and do the TLS handshake manually
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{Transport: transport}
	url := fmt.Sprintf("%s://%s:%d", targetScheme, targetHost, targetPort)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get via proxy: %w", err)
	}
	defer resp.Body.Close()

	if err := responseExpected(resp, targetServerResponseStatusCode, targetServerResponseBody); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	return nil
}

func responseExpected(resp *http.Response, expectedStatusCode int, expectedResponse []byte) error {
	if expectedStatusCode != resp.StatusCode {
		return fmt.Errorf("returned wrong status code: got %d want %d",
			resp.StatusCode, targetServerResponseStatusCode)
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
			return fmt.Errorf("returned nTotal == responseLen, but haven't seen io.EOF:\ngot: '%s'\nwant: '%s'",
				response, expectedResponse)
		}
	}
	response = response[:nTotal]
	if len(expectedResponse) != len(response) {
		return fmt.Errorf("returned wrong response length:\ngot %d: '%s'\nwant %d: '%s'\n",
			len(response), response, len(expectedResponse), expectedResponse)
	}
	for i := range response {
		if response[i] != expectedResponse[i] {
			return fmt.Errorf("returned response has mismatch at character #%d\ngot: '%s'\nwant: '%s'",
				i, response, expectedResponse)
		}
	}
	return nil
}

func checkScionConfiguration(daemonAddr string) error {
	// all pan library components should use this address as well
	if daemonAddr != "" {
		os.Setenv("SCION_DAEMON_ADDRESS", daemonAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second) // keep tests fast
	defer cancel()

	// check if we are on a scion enabled host
	sciond, err := findSciond(ctx)
	if err != nil {
		return err
	}

	ia, err := sciond.LocalIA(ctx)
	if err != nil {
		return err
	}

	addr, err := pan.ResolveUDPAddr(ctx, scionHost+":0") // dummy port
	if err != nil {
		return err
	}

	if ia.String() != addr.IA.String() {
		return fmt.Errorf("E2E is misconfigured\n\ttest target host '%s' must point to the same IA as the scion daemon\n\tgot %s, want %s\n\t(add '%s,[127.0.0.1] %s' to /etc/hosts)", scionHost, addr.IA, ia, ia, scionHost)
	}

	return nil
}

func findSciond(ctx context.Context) (daemon.Connector, error) {
	address, ok := os.LookupEnv("SCION_DAEMON_ADDRESS")
	if !ok {
		address = daemon.DefaultAPIAddress
	}

	sciondConn, err := daemon.NewService(address).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to SCIOND at %s (provide as flag or override with SCION_DAEMON_ADDRESS): %w", address, err)
	}
	return sciondConn, nil
}
