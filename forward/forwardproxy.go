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

package forwardproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"go.uber.org/zap"

	"github.com/scionassociation/http-scion/forward/ioutils"
	"github.com/scionassociation/http-scion/forward/panpolicy"
	"github.com/scionassociation/http-scion/forward/resolver"
	"github.com/scionassociation/http-scion/forward/session"
)

const (
	// NOTE: if this changes, the browser extension has to be adapted
	APIPathPrefix  = ""
	APIPolicyPath  = APIPathPrefix + "/policy"
	APIPathUsage   = APIPathPrefix + "/path-usage"
	APIResolveURL  = APIPathPrefix + "/redirect"
	APIResolveHost = APIPathPrefix + "/resolve"
)

var (
	// Interface guards
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

func init() {
	caddy.RegisterModule(Handler{})
}

// ResolveHandler defines an interface for handling HTTP requests related to
// host resolution and redirection. Implementations of this interface should
// provide mechanisms to handle redirection back or errors, as well as host
// resolution requests.
type ResolveHandler interface {
	HandleRedirectBackOrError(w http.ResponseWriter, r *http.Request) error
	HandleHostResolutionRequest(w http.ResponseWriter, r *http.Request) error
}

// Handler implements a forward proxy.
type Handler struct {
	logger *zap.Logger

	// Host(s) (and ports) of the proxy. When you configure a client,
	// you will give it the host (and port) of the proxy to use.
	// Default: empty
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"`

	// How long to wait before timing out resolve requests.
	// Default: 5s
	ResolveTimeout caddy.Duration `json:"resolve_timeout,omitempty"`

	// How long to wait before timing out initial TCP connections.
	// Default: 5s
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// Whether to disable purging of inactive dialers.
	// Default: false
	DisablePurgeInactiveDialers bool `json:"disable_purge_inactive_dialers,omitempty"`

	// How long to wait before a custom scion dialer with no open connections is purged.
	// Default: 10m
	PurgeTimeout caddy.Duration `json:"purge_timeout,omitempty"`

	// In what interval the custom scion dialer should be checked.
	// Default: 1m
	PurgeInterval caddy.Duration `json:"purge_interval,omitempty"`

	metricsHandler caddyhttp.Handler

	policyManager     panpolicy.DialerManager
	scionHostResolver ResolveHandler

	resolver resolver.Resolver
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.ResolveTimeout <= 0 {
		h.ResolveTimeout = caddy.Duration(5 * time.Second)
	}

	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(5 * time.Second)
	}

	if h.PurgeTimeout <= 0 {
		h.PurgeTimeout = caddy.Duration(10 * time.Minute)
	}

	if h.PurgeInterval <= 0 {
		h.PurgeInterval = caddy.Duration(1 * time.Minute)
	}

	h.scionHostResolver = resolver.NewScionHostResolver(
		h.logger.With(zap.String("component", "scion-host-resolver")),
		time.Duration(h.ResolveTimeout),
	)

	h.policyManager = panpolicy.NewPolicyManager(
		h.logger.With(zap.String("component", "policy-manager")),
		time.Duration(h.DialTimeout),
		!h.DisablePurgeInactiveDialers,
		time.Duration(h.PurgeTimeout),
		time.Duration(h.PurgeInterval),
	)
	if err := h.policyManager.Start(); err != nil {
		return err
	}

	h.metricsHandler = panpolicy.NewMetricsHandler(
		h.policyManager,
		h.logger.With(zap.String("component", "metrics-handler")),
	)
	h.resolver = resolver.NewPANResolver(
		h.logger.With(zap.String("component", "resolver")),
		time.Duration(h.ResolveTimeout),
	)

	return nil
}

func (h Handler) Cleanup() error {
	err := h.policyManager.Stop()
	if err != nil {
		return err
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Hosts.Match(r) && r.Method != http.MethodConnect {
		// pass non-CONNECT requests to hostname to the proxy API
		log := h.logger.With(zap.String("path", r.URL.Path))
		switch r.URL.Path {
		case APIPolicyPath:
			log.Debug("Setting policy.")
			return h.policyManager.ServeHTTP(w, r)
		case APIPathUsage:
			log.Debug("Getting path metrics.")
			return h.metricsHandler.ServeHTTP(w, r)
		case APIResolveURL:
			log.Debug("Resolve URL.")
			return h.scionHostResolver.HandleRedirectBackOrError(w, r)
		case APIResolveHost:
			log.Debug("Resolve host.")
			return h.scionHostResolver.HandleHostResolutionRequest(w, r)
		default:
			// serve next caddy handler
			log.Debug("Ignoring non matching API path.")
			return next.ServeHTTP(w, r)
		}
	}

	// get session
	err := h.parseCookieFromProxyAuth(w, r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// parse session date from cookie e.g. policy
	sessionData, err := session.GetSessionData(h.logger, r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	h.logger.Debug("Having session.", zap.String("session-id", sessionData.ID))

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}
	h.logger.Debug("Resolving host.", zap.String("host", hostPort))
	addr, _ := h.resolver.Resolve(r.Context(), hostPort)

	// get dialer based on policy and destination address
	useScion := !addr.IsZero()
	dialer, err := h.policyManager.GetDialer(sessionData, useScion)
	if err != nil {
		return err
	}

	if r.Method == http.MethodConnect {
		h.logger.Debug("Tunneling.", zap.String("host", r.Host))
		return h.tunnelRequest(w, r, dialer)
	}

	h.logger.Debug("Proxying.", zap.String("host", r.Host), zap.String("method", r.Method))
	return h.forwardRequest(w, r, dialer)
}

func (h Handler) parseCookieFromProxyAuth(w http.ResponseWriter, r *http.Request) error {
	// the path policy cookie is passed in the proxy-authorization header as the cookie
	username, cookie, err := proxyBasicAuth(r)
	if err != nil || username != "policy" {
		h.logger.Warn("Invalid or not provided proxy authorization header.", zap.Error(err))

		w.Header().Set("Proxy-Authenticate", "Basic realm=caddy-scion-forward-proxy") // realm is a garbage value
		return caddyhttp.Error(http.StatusProxyAuthRequired, fmt.Errorf("required to pass valid proxy authorization header"))
	}

	h.logger.Debug("Proxy authorization header provided.")

	// make sure there is only one policy cookie
	removeForwardProxyCookie(r)

	if len(cookie) == 0 {
		return nil
	}

	// inspired by http.Request.AddCookie
	if c := r.Header.Get("Cookie"); c != "" {
		r.Header.Set("Cookie", c+"; "+cookie)
	} else {
		r.Header.Set("Cookie", cookie)
	}

	return nil
}

func proxyBasicAuth(r *http.Request) (username, password string, err error) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", nil
	}
	return parseBasicAuth(auth)
}

func parseBasicAuth(auth string) (username, password string, err error) {
	const prefix = "Basic "
	// Case insensitive prefix match.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", fmt.Errorf("authorization header format does not start with 'Basic '")
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", fmt.Errorf("failed to base64 decode authorization header: %v", err)
	}
	cs := string(c)
	username, password, ok := strings.Cut(cs, ":")
	if !ok || username != "policy" {
		return "", "", fmt.Errorf("authorization header format does not contain policy:value %s", cs)
	}
	return username, password, nil
}

func (h Handler) tunnelRequest(w http.ResponseWriter, r *http.Request, dialer panpolicy.PANDialer) error {
	if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
		if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
			return caddyhttp.Error(http.StatusBadRequest,
				fmt.Errorf("CONNECT request has :scheme and/or :path pseudo-header fields"))
		}
	}

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}

	targetConn, err := dialer.DialContext(r.Context(), "tcp", hostPort)
	if err != nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("failed to setup tunnel: %v", err))
	}
	defer targetConn.Close()
	h.logger.Debug("Set up tunnel.", zap.String("remote-address", targetConn.RemoteAddr().String()))

	switch r.ProtoMajor {
	case 1: // http1: hijack the whole flow
		return h.serveHijack(w, targetConn)
	case 2: // http2: keep reading from "request" and writing into same response
		fallthrough
	case 3:
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
		err := http.NewResponseController(w).Flush()
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError,
				fmt.Errorf("ResponseWriter flush error: %v", err))
		}
		return ioutils.DualStream(targetConn, r.Body, w)
	default:
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP major version: %d", r.ProtoMajor))
	}
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func (h Handler) serveHijack(w http.ResponseWriter, targetConn net.Conn) error {
	clientConn, bufReader, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()
	// bufReader may contain unprocessed buffered data from the client.
	if bufReader != nil {
		// snippet borrowed from `proxy` plugin
		if n := bufReader.Reader.Buffered(); n > 0 {
			rbuf, err := bufReader.Reader.Peek(n)
			if err != nil {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			_, _ = targetConn.Write(rbuf)

		}
	}
	// Since we hijacked the connection, we lost the ability to write and flush headers via w.
	// Let's handcraft the response and send it manually.
	res := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	res.Header.Set("Server", "Caddy")

	buf := bufio.NewWriter(clientConn)
	err = res.Write(buf)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to write response: %v", err))
	}
	err = buf.Flush()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to send response to client: %v", err))
	}

	return ioutils.DualStream(targetConn, clientConn, clientConn)
}

func (h Handler) forwardRequest(w http.ResponseWriter, r *http.Request, dialer panpolicy.PANDialer) error {
	// Scheme has to be appended to avoid `unsupported protocol scheme ""` error.
	// `http://` is used, since this initial request itself is always HTTP, regardless of what client and server
	// may speak afterwards.
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.RequestURI = ""

	removeHopByHopHeaders(r.Header)
	removeForwardProxyCookie(r)

	r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")

	// https://tools.ietf.org/html/rfc7230#section-5.7.1
	r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")

	if r.Body != nil && (r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
		// make sure request is idempotent and could be retried by saving the Body
		// None of those methods are supposed to have body,
		// but we still need to copy the r.Body, even if it's empty
		rBodyBuf, err := io.ReadAll(r.Body)
		if err != nil {
			return caddyhttp.Error(http.StatusBadRequest,
				fmt.Errorf("failed to read request body: %v", err))
		}
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(rBodyBuf)), nil
		}
		r.Body, _ = r.GetBody()
	}

	// is the same as http.DefaultTransport but not as the Roundtripper type so we can set the Dialer
	transport := shttp.DefaultTransport.Clone()
	transport.DialContext = dialer.DialContext

	resp, err := transport.RoundTrip(r)
	if err != nil {
		if _, ok := err.(caddyhttp.HandlerError); ok {
			return err
		}
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("failed to read response: %v", err))
	}
	defer resp.Body.Close()

	return forwardResponse(w, resp)
}

func removeForwardProxyCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == session.SessionName {
			continue
		}
		r.AddCookie(c)
	}
}

// Removes hop-by-hop headers, and writes response into ResponseWriter.
func forwardResponse(w http.ResponseWriter, response *http.Response) error {
	w.Header().Del("Server") // remove Server: Caddy, append via instead
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	removeHopByHopHeaders(response.Header)
	copyHeader(w.Header(), response.Header)

	w.WriteHeader(response.StatusCode)

	// transfer body
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]
	defer bufferPool.Put(bufPtr)
	_, err := io.CopyBuffer(w, response.Body, buf)

	return err
}

// https://github.com/golang/go/blob/go1.21.6/src/net/http/httputil/reverseproxy.go#L281-L287
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopByHopHeaders removes hop-by-hop headers.
// https://github.com/golang/go/blob/go1.21.6/src/net/http/httputil/reverseproxy.go#L566-L581
func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		h.Del(f)
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
// https://github.com/golang/go/blob/go1.21.6/src/net/http/httputil/reverseproxy.go#L294-L304
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 0, 32*1024)
		return &buffer
	},
}
