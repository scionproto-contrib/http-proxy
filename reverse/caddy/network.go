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

package caddy

import (
	"context"
	"crypto/tls"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"

	"github.com/scionassociation/http-scion/reverse"
)

var (
	globalNetwork = reverse.Network{
		Pool:         NewUsagePool[string, *reverse.ReusableListener](),
		QUICListener: &panListener{},
	}
)

func init() {
	globalNetwork.SetNopLogger()
	caddy.RegisterNetwork(reverse.SCIONNetwork, globalNetwork.ListenSCION) // used for HTTP over SCION
}

// Interface guards
var (
	_ caddy.ListenerFunc = (*reverse.Network)(nil).ListenSCION
)

type panListener struct{}

func (*panListener) Listen(ctx context.Context, local netip.AddrPort, selector pan.ReplySelector,
	tlsConf *tls.Config, quicConfig *quic.Config) (*quic.Listener, error) {
	return pan.ListenQUIC(ctx, local, selector, tlsConf, quicConfig)
}
