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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	scionNetwork = "scion"
)

var (
	globalNetwork = Network{
		scionPool:    NewUsagePool[string, *listener](),
		QUICListener: &panListener{},
	}

	// Interface guards
	_ caddy.ListenerFunc = (*Network)(nil).ListenSCION

	_ net.Listener = (*listener)(nil)
)

func init() {
	globalNetwork.logger.Store(zap.NewNop())

	caddy.RegisterNetwork(scionNetwork, globalNetwork.ListenSCION) // used for HTTP over SCION
}

// QUICListener defines an interface for creating a QUIC listener.
// It provides a method to start listening for incoming QUIC connections.
// This interface is used to allow for testing.
type QUICListener interface {
	Listen(ctx context.Context, local netip.AddrPort, selector pan.ReplySelector,
		tlsConf *tls.Config, quicConfig *quic.Config) (*quic.Listener, error)
}

type panListener struct{}

func (*panListener) Listen(ctx context.Context, local netip.AddrPort, selector pan.ReplySelector,
	tlsConf *tls.Config, quicConfig *quic.Config) (*quic.Listener, error) {
	return pan.ListenQUIC(ctx, local, selector, tlsConf, quicConfig)
}

// Network is a custom network that allows to listen on SCION addresses.
type Network struct {
	scionPool *UsagePool[string, *listener]

	logger       atomic.Pointer[zap.Logger]
	QUICListener QUICListener
}

// SetLogger sets the logger for the network. It is safe to access concurrently.
func (n *Network) SetLogger(logger *zap.Logger) {
	n.logger.Store(logger)
}

// Logger gets the logger.
func (n *Network) Logger() *zap.Logger {
	return n.logger.Load()
}

func (n *Network) ListenSCION(
	ctx context.Context,
	network string,
	address string,
	cfg net.ListenConfig,
) (any, error) {
	log := n.Logger().With(zap.String("network", network), zap.String("address", address))

	if network != scionNetwork {
		return nil, fmt.Errorf("network not supported: %s", network)
	}

	l, loaded, err := n.scionPool.LoadOrNew(address, func() (caddy.Destructor, error) {
		laddr, err := pan.ParseOptionalIPPort(address)
		if err != nil {
			log.Error("Failed to parse address.", zap.Error(err))
			return nil, err
		}

		tlsCfg := &tls.Config{
			NextProtos:   []string{quicutil.SingleStreamProto},
			Certificates: quicutil.MustGenerateSelfSignedCert(),
		}
		quicListener, err := n.QUICListener.Listen(ctx, laddr, nil, tlsCfg, nil)
		if err != nil {
			log.Error("Failed to listen on QUIC.", zap.Error(err))
			return nil, err
		}

		log.Debug("Created new listener.")
		return &listener{
			SingleStreamListener: &quicutil.SingleStreamListener{Listener: quicListener},
			addr:                 address,
			network:              n,
		}, nil
	})
	if err != nil {
		log.Error("Failed to create new listener.", zap.Error(err))
		return nil, err
	}

	log.Debug("Created new listener.", zap.Bool("reuse", loaded))
	return l, err
}

// listener makes it possible to reuse the same quicutil.SingleStreamListener.
// This is especially important for making Caddy's config hot-reload possible.
// It is designed to work in conjuction of the scion usage pool.
type listener struct {
	*quicutil.SingleStreamListener
	addr    string
	network *Network
}

// Close reduces the usage count of the listener.
// The actual Close method is called, when the usage count reached 0.
func (l *listener) Close() error {
	_, err := l.network.scionPool.Delete(l.addr)
	return err
}

// Destruct is called, when the listener is deallocated, i.e. the usage count reached 0.
func (l *listener) Destruct() error {
	l.network.Logger().Debug("Destroying listener.", zap.String("addr", l.addr))
	defer l.network.Logger().Debug("Destroyed listener.", zap.String("addr", l.addr))

	return l.SingleStreamListener.Close()
}
