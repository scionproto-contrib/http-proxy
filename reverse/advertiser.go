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
	_ caddyhttp.MiddlewareHandler = (*SCIONAdvertiserHandler)(nil)
	_ caddy.Provisioner           = (*SCIONAdvertiserHandler)(nil)
)

func init() {
	caddy.RegisterModule(SCIONAdvertiserHandler{})
}

type SCIONAdvertiserHandler struct {
	StrictScion string `json:"Strict-SCION,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SCIONAdvertiserHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.advertise_scion",
		New: func() caddy.Module { return new(SCIONAdvertiserHandler) },
	}
}

func (s *SCIONAdvertiserHandler) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s SCIONAdvertiserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s.logger.Debug("Checking for scion traffic.",
		zap.String("remote-address", r.RemoteAddr))

	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err != nil {
		if w.Header().Get("Strict-SCION") == "" {
			w.Header().Set("Strict-SCION", s.StrictScion)
		}
	}
	return next.ServeHTTP(w, r)
}
