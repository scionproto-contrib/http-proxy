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

package reverse

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	SCIONNetwork = "scion"
)

// QUICListener defines an interface for creating a QUIC listener.
// It provides a method to start listening for incoming QUIC connections.
// This interface is used to allow for testing.
type QUICListener interface {
	Listen(ctx context.Context, local netip.AddrPort, selector pan.ReplySelector,
		tlsConf *tls.Config, quicConfig *quic.Config) (*quic.Listener, error)
}

// Pool defines the interface for thread-safe map implementations
// that pools values based on usage (reference counting).
type Pool[K comparable, V any] interface {
	LoadOrNew(key K, construct func() (Destructor, error)) (V, bool, error)
	Delete(key K) (bool, error)
}

// Network is a custom network that allows listening on SCION addresses.
type Network struct {
	Pool Pool[string, *ReusableListener]

	logger       atomic.Pointer[zap.Logger]
	QUICListener QUICListener
}

// SetNopLogger sets the logger to a no-operation logger. This can be useful
// as a placeholder or in scenarios where logging is not needed or should be suppressed entirely.
func (n *Network) SetNopLogger() {
	n.logger.Store(zap.NewNop())
}

// SetLogger sets the logger for the network. It is safe to access concurrently.
func (n *Network) SetLogger(logger *zap.Logger) {
	n.logger.Store(logger)
}

// Logger gets the logger.
func (n *Network) Logger() *zap.Logger {
	return n.logger.Load()
}

// Destructor defines an interface for objects that can be destructed.
type Destructor interface {
	Destruct() error
}

// ListenSCION listens on a SCION address.
func (n *Network) ListenSCION(
	ctx context.Context,
	network string,
	address string,
	cfg net.ListenConfig,
) (any, error) {
	log := n.Logger().With(zap.String("network", network), zap.String("address", address))

	if network != SCIONNetwork {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	l, loaded, err := n.Pool.LoadOrNew(address, func() (Destructor, error) {
		laddr, err := pan.ParseOptionalIPPort(address)
		if err != nil {
			log.Error("Failed to parse address", zap.Error(err))
			return nil, err
		}

		tlsCfg := &tls.Config{
			NextProtos:   []string{quicutil.SingleStreamProto},
			Certificates: quicutil.MustGenerateSelfSignedCert(),
		}
		quicListener, err := n.QUICListener.Listen(ctx, laddr, nil, tlsCfg, nil)
		if err != nil {
			log.Error("Failed to listen on QUIC", zap.Error(err))
			return nil, err
		}

		log.Debug("Created new listener")
		return &ReusableListener{
			SingleStreamListener: &quicutil.SingleStreamListener{Listener: quicListener},
			addr:                 address,
			network:              n,
		}, nil
	})
	if err != nil {
		log.Error("Failed to create new listener", zap.Error(err))
		return nil, err
	}

	log.Debug("Created new listener", zap.Bool("reuse", loaded))
	return l, nil
}

// ReusableListener makes it possible to reuse the same quicutil.SingleStreamListener.
// This is especially important for making Caddy's config hot-reload possible.
// It is designed to work in conjunction with a pool implementation.
type ReusableListener struct {
	*quicutil.SingleStreamListener
	addr    string
	network *Network
}

// Close reduces the usage count of the listener.
// The actual Close method is called when the usage count reaches 0.
func (l *ReusableListener) Close() error {
	_, err := l.network.Pool.Delete(l.addr)
	return err
}

// Destruct is called when the listener is deallocated, i.e., the usage count reaches 0.
func (l *ReusableListener) Destruct() error {
	l.network.Logger().Debug("Destroying listener", zap.String("addr", l.addr))
	defer l.network.Logger().Debug("Destroyed listener", zap.String("addr", l.addr))

	return l.SingleStreamListener.Close()
}
