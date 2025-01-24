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

package dummy

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"

	"github.com/scionproto-contrib/http-proxy/networks"
)

const (
	SCION      = "scion"
	SCIONDummy = "scion+dummy"
)

// Network is a custom network that allows listening on SCION addresses.
type Network struct {
	Pool networks.Pool[string, networks.Reusable]

	logger   atomic.Pointer[zap.Logger]
	listener listener
}

// listener defines an interface for creating a QUIC listener.
// It provides a method to start listening for incoming QUIC connections.
// This interface is used to allow for testing.
type listener interface {
	listen(ctx context.Context,
		network *Network,
		laddr *snet.UDPAddr,
		cfg net.ListenConfig) (networks.Destructor, error)
}

func NewNetwork(pool networks.Pool[string, networks.Reusable]) *Network {
	return &Network{
		Pool:     pool,
		listener: &listenerSCIONDummy{},
	}
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

func (n *Network) Listen(
	ctx context.Context,
	network string,
	address string,
	cfg net.ListenConfig,
) (any, error) {
	if network != SCIONDummy && network != SCION {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	laddr, err := snet.ParseUDPAddr(address)
	if err != nil {
		return nil, fmt.Errorf("parsing listening address: %w", err)
	}
	if laddr.Host.Port == 0 {
		return nil, fmt.Errorf("wildcard port not supported: %s", address)
	}
	key := networks.PoolKey(network, laddr.String())
	c, loaded, err := n.Pool.LoadOrNew(key, func() (networks.Destructor, error) {
		return n.listener.listen(ctx, n, laddr, cfg)
	})
	if err != nil {
		return nil, err
	}
	n.Logger().Debug("created new listener", zap.String("addr", key), zap.Bool("reuse", loaded))
	return c, nil
}

type listenerSCIONDummy struct {
}

func (l *listenerSCIONDummy) listen(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	cfg net.ListenConfig,
) (networks.Destructor, error) {
	return &dummyListener{
		address: laddr,
		network: network,
	}, nil
}

// blockedListener is a net.Listener that will never accept a connection. It
// blocks until the underlying connection is closed.
type dummyListener struct {
	address *snet.UDPAddr
	network *Network
}

func (l *dummyListener) LocalAddr() net.Addr {
	return l.Addr()
}

func (l *dummyListener) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, fmt.Errorf("not implemented")
}

func (l *dummyListener) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, fmt.Errorf("not implemented")
}

func (l *dummyListener) SetDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (l *dummyListener) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (l *dummyListener) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (l *dummyListener) Addr() net.Addr {
	return l.address
}

func (l *dummyListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}

func (l *dummyListener) Close() error {
	_, err := l.network.Pool.Delete(networks.PoolKey(SCIONDummy, l.address.String()))
	return err
}

func (l *dummyListener) Destruct() error {
	l.network.Logger().Debug("destroying listener", zap.String("addr", l.address.String()))
	defer l.network.Logger().Debug("destroyed listener", zap.String("addr", l.address.String()))
	return nil
}
