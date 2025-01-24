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

package native

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
	SCIONNetwork = "scion"
	SCIONUDP     = "scion+udp"
)

// listener defines an interface for creating a QUIC listener.
// It provides a method to start listening for incoming QUIC connections.
// This interface is used to allow for testing.
type listener interface {
	listen(ctx context.Context,
		network *Network,
		laddr *snet.UDPAddr,
		cfg net.ListenConfig) (networks.Destructor, error)
}

// Network is a custom network that allows to listen on SCION addresses.
type Network struct {
	Pool              networks.Pool[string, *conn]
	PacketConnMetrics snet.SCIONPacketConnMetrics

	logger   atomic.Pointer[zap.Logger]
	listener listener
}

func NewNetwork(pool networks.Pool[string, *conn]) *Network {
	return &Network{
		Pool:     pool,
		listener: &listenerSCIONUDP{},
	}
}

// SetLogger sets the logger for the network. It is safe to access concurrently.
func (n *Network) SetLogger(logger *zap.Logger) {
	n.logger.Store(logger)
}

func (n *Network) SetPacketConnMetrics(metrics snet.SCIONPacketConnMetrics) {
	n.PacketConnMetrics = metrics
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
	if network != SCIONUDP {
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

type listenerSCIONUDP struct {
}

func (l *listenerSCIONUDP) listen(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	cfg net.ListenConfig,
) (networks.Destructor, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	sd, err := networks.SCIONDConn(laddr.IA)
	if err != nil {
		network.Logger().Error("failed to connect to SCIOND", zap.Error(err))
		return nil, err
	}

	n := &snet.SCIONNetwork{
		Topology:          sd,
		SCMPHandler:       ignoreSCMP{},
		PacketConnMetrics: network.PacketConnMetrics,
	}

	c, err := n.Listen(ctx, "udp", laddr.Host)
	if err != nil {
		network.Logger().Error("failed to listen on scion+udp", zap.Error(err))
		return nil, err
	}

	network.Logger().Debug("created new scion+udp listener", zap.String("addr", laddr.String()))
	return &conn{
		PacketConn: c,
		addr:       laddr.String(),
		network:    network,
	}, nil
}

type conn struct {
	net.PacketConn
	addr    string
	network *Network
}

// Close removes the reference in the usage pool. If the references go to zero,
// the connection is destroyed.
func (c *conn) Close() error {
	_, err := c.network.Pool.Delete(networks.PoolKey(SCIONUDP, c.addr))
	return err
}

// Destruct closes the connection. It is called by the usage pool when the
// reference count goes to zero.
func (c *conn) Destruct() error {
	c.network.Logger().Debug("destroying listener", zap.String("addr", c.addr))
	defer c.network.Logger().Debug("destroyed listener", zap.String("addr", c.addr))

	return c.PacketConn.Close()
}

// ignoreSCMP is a SCMP handler that ignores all SCMP messages. This is required
// because SCMP error messages should not close the accept loop.
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}
