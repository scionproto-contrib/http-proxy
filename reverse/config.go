// Copyright 2024 Anapaya Systems, ETH Zurich
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
	"github.com/caddyserver/caddy/v2"
)

var (
	// Interface guards
	_ caddy.Module      = (*SCION)(nil)
	_ caddy.Provisioner = (*SCION)(nil)
	_ caddy.App         = (*SCION)(nil)
)

func init() {
	caddy.RegisterModule(SCION{})
}

// SCION implements a caddy module. Currently, it is used to initialize the
// logger for the global network. In the future, additional configuration can be
// parsed with this component.
//
// Has to be configured as Caddy app to be executed.
type SCION struct{}

func (SCION) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "scion",
		New: func() caddy.Module {
			return new(SCION)
		},
	}
}

func (s *SCION) Provision(ctx caddy.Context) error {
	globalNetwork.SetLogger(ctx.Logger())
	return nil
}

func (s *SCION) Start() error {
	// no-op
	return nil
}

func (s *SCION) Stop() error {
	// no-op
	return nil
}
