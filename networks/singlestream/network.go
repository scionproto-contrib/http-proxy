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

package singlestream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"

	"github.com/scionproto-contrib/http-proxy/networks"
)

const (
	SCIONSingleStream = "scion+single-stream"
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

// Network is a custom network that allows listening on SCION addresses.
type Network struct {
	Pool              networks.Pool[string, networks.Reusable]
	PacketConnMetrics snet.SCIONPacketConnMetrics

	logger   atomic.Pointer[zap.Logger]
	listener listener
}

func NewNetwork(pool networks.Pool[string, networks.Reusable]) *Network {
	return &Network{
		Pool:     pool,
		listener: &listenerSCION{},
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
	if network != SCIONSingleStream {
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

type listenerSCION struct {
}

func (l *listenerSCION) listen(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	cfg net.ListenConfig,
) (networks.Destructor, error) {
	tlsCfg := &tls.Config{
		NextProtos:   []string{quicutil.SingleStreamProto},
		Certificates: quicutil.MustGenerateSelfSignedCert(),
	}
	quicListener, err := listenQUIC(ctx, network, laddr, tlsCfg, nil)
	if err != nil {
		network.Logger().Error("failed to listen on QUIC", zap.Error(err))
		return nil, err
	}

	network.Logger().Debug("created new listener", zap.String("addr", laddr.String()))
	return &reusableListener{
		SingleStreamListener: &quicutil.SingleStreamListener{QUICListener: quicListener},
		addr:                 laddr.String(),
		network:              network,
	}, nil
}

// reusableListener allows reusing the same quicutil.SingleStreamListener.
// It works in conjunction with a pool implementation to manage usage.
type reusableListener struct {
	*quicutil.SingleStreamListener
	addr    string
	network *Network
}

// Close decreases the usage count of the listener.
// The actual Close method is invoked when the usage count reaches zero.
func (l *reusableListener) Close() error {
	_, err := l.network.Pool.Delete(networks.PoolKey(SCIONSingleStream, l.addr))
	return err
}

// Destruct is called when the listener is deallocated, i.e., when the usage count reaches zero.
func (l *reusableListener) Destruct() error {
	l.network.Logger().Debug("destroying listener", zap.String("addr", l.addr))
	defer l.network.Logger().Debug("destroyed listener", zap.String("addr", l.addr))

	return l.SingleStreamListener.Close()
}

type quicListener struct {
	*quic.Listener
	conn net.PacketConn
}

func (l *quicListener) Close() error {
	err := l.Listener.Close()
	l.conn.Close()
	return err
}

func listenQUIC(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	tlsConf *tls.Config,
	quicConfig *quic.Config) (pan.QUICListener, error) {

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

	conn, err := n.Listen(ctx, "udp", laddr.Host)
	if err != nil {
		network.Logger().Error("failed to listen on scion+udp", zap.Error(err))
		return nil, err
	}
	listener, err := quic.Listen(conn, tlsConf, quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &quicListener{Listener: listener, conn: conn}, nil
}

// ignoreSCMP is a SCMP handler that ignores all SCMP messages. This is required
// because SCMP error messages should not close the accept loop.
type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}
