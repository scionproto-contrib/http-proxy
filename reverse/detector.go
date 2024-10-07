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

package reverseproxy

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"
)

var (
	// Interface guards
	_ caddyhttp.MiddlewareHandler = (*SCIONDetectorHandler)(nil)
	_ caddy.Provisioner           = (*SCIONDetectorHandler)(nil)
)

func init() {
	caddy.RegisterModule(SCIONDetectorHandler{})
}

type SCIONDetectorHandler struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SCIONDetectorHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.detect_scion",
		New: func() caddy.Module { return new(SCIONDetectorHandler) },
	}
}

func (s *SCIONDetectorHandler) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (SCIONDetectorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err == nil {
		r.Header.Add("X-SCION", "on")
		r.Header.Add("X-SCION-Remote-Addr", r.RemoteAddr)
	} else {
		r.Header.Add("X-SCION", "off")
	}
	return next.ServeHTTP(w, r)
}
