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

package caddy

import (
	"net/http"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/scionproto-contrib/http-proxy/forward"
	"github.com/scionproto-contrib/http-proxy/forward/utils"
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

// HTTPHandler is an interface for handling HTTP requests.
type HTTPHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request) error
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

	coreProxy *forward.CoreProxy
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

	h.coreProxy = forward.NewCoreProxy(h.logger, time.Duration(h.ResolveTimeout), time.Duration(h.DialTimeout), time.Duration(h.PurgeTimeout), time.Duration(h.PurgeInterval), h.DisablePurgeInactiveDialers)
	return h.coreProxy.Initialize()
}

// Cleanup cleans up the handler.
func (h *Handler) Cleanup() error {
	return h.coreProxy.Cleanup()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Hosts.Match(r) && r.Method != http.MethodConnect {
		log := h.logger.With(zap.String("path", r.URL.Path))
		var err error
		switch r.URL.Path {
		case APIPolicyPath:
			log.Debug("Setting policy.")
			err = h.coreProxy.HandlePolicyPath(w, r)
		case APIPathUsage:
			log.Debug("Getting path metrics.")
			err = h.coreProxy.HandlePathUsage(w, r)
		case APIResolveURL:
			log.Debug("Resolve URL.")
			err = h.coreProxy.HandleResolveURL(w, r)
		case APIResolveHost:
			log.Debug("Resolve host.")
			err = h.coreProxy.HandleResolveHost(w, r)
		default:
			log.Debug("Ignoring non matching API path.")
			return next.ServeHTTP(w, r)
		}
		if err != nil {
			return caddyError(err)
		}
		return nil
	}
	if err := h.coreProxy.HandleTunnelRequest(w, r); err != nil {
		return caddyError(err)
	}
	return nil
}

func caddyError(err error) error {
	if he, ok := err.(*utils.HandlerError); ok {
		return caddyhttp.Error(he.StatusCode, he.Err)
	}
	return caddyhttp.Error(http.StatusInternalServerError, err)
}
