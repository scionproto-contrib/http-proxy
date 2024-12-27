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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/scionproto/scion/pkg/log"
	"go.uber.org/zap"
)

const (
	SCION3     = "scion3"
	SCION3QUIC = "scion3+quic"
	SCION      = "scion"
	SCIONDummy = "scion+dummy"
)

// Destructor defines an interface for objects that can be destructed.
type Destructor interface {
	Destruct() error
}

// Reusable is an interface to an object that can be used multiple times.
// It extends the Destructor interface with a Close method. The Close method
// should be called when the object is no longer needed from the caller.
type Reusable interface {
	Destructor
	Close() error
}

// Pool defines the interface for thread-safe map implementations
// that pools values based on usage (reference counting).
type Pool[K comparable, V any] interface {
	LoadOrNew(key K, construct func() (Destructor, error)) (V, bool, error)
	Delete(key K) (bool, error)
}

// listener defines an interface for creating a QUIC listener.
// It provides a method to start listening for incoming QUIC connections.
// This interface is used to allow for testing.
type listener interface {
	listen(ctx context.Context,
		network *Network,
		laddr netip.AddrPort,
		cfg net.ListenConfig) (Destructor, error)
}

// Network is a custom network that allows listening on SCION addresses.
type Network struct {
	Pool Pool[string, Reusable]

	logger             atomic.Pointer[zap.Logger]
	listenerSCION      listener
	listenerSCION3QUIC listener
	listenerSCIONDummy listener
}

func NewNetwork(pool Pool[string, Reusable]) *Network {
	return &Network{
		Pool:               pool,
		listenerSCION:      &listenerSCION{},
		listenerSCION3QUIC: &listenerSCION3QUIC{},
		listenerSCIONDummy: &listenerSCIONDummy{},
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
	var l listener
	switch network {
	case SCION:
		l = n.listenerSCION
	case SCION3QUIC:
		l = n.listenerSCION3QUIC
	case SCION3:
		fallthrough
	case SCIONDummy:
		l = n.listenerSCIONDummy
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	laddr, err := parseIPPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing listening address: %w", err)
	}
	if laddr.Port() == 0 {
		return nil, fmt.Errorf("wildcard port not supported: %s", address)
	}
	key := poolKey(network, laddr.String())
	c, loaded, err := n.Pool.LoadOrNew(key, func() (Destructor, error) {
		return l.listen(ctx, n, laddr, cfg)
	})
	if err != nil {
		return nil, err
	}
	n.Logger().Debug("created new listener", zap.String("addr", key), zap.Bool("reuse", loaded))
	return c, err
}

type listenerSCION struct {
}

func (l *listenerSCION) listen(
	ctx context.Context,
	network *Network,
	laddr netip.AddrPort,
	cfg net.ListenConfig,
) (Destructor, error) {
	tlsCfg := &tls.Config{
		NextProtos:   []string{quicutil.SingleStreamProto},
		Certificates: quicutil.MustGenerateSelfSignedCert(),
	}
	quicListener, err := pan.ListenQUIC(ctx, laddr, nil, tlsCfg, nil)
	if err != nil {
		log.Error("Failed to listen on QUIC", zap.Error(err))
		return nil, err
	}

	log.Debug("Created new listener")
	return &reusableListener{
		SingleStreamListener: &quicutil.SingleStreamListener{QUICListener: quicListener},
		addr:                 laddr.String(),
		network:              network,
	}, nil
}

// reusableListener makes it possible to reuse the same quicutil.SingleStreamListener.
// This is especially important for making Caddy's config hot-reload possible.
// It is designed to work in conjunction with a pool implementation.
type reusableListener struct {
	*quicutil.SingleStreamListener
	addr    string
	network *Network
}

// Close reduces the usage count of the listener.
// The actual Close method is called when the usage count reaches 0.
func (l *reusableListener) Close() error {
	_, err := l.network.Pool.Delete(poolKey(SCION, l.addr))
	return err
}

// Destruct is called when the listener is deallocated, i.e., the usage count reaches 0.
func (l *reusableListener) Destruct() error {
	l.network.Logger().Debug("Destroying listener", zap.String("addr", l.addr))
	defer l.network.Logger().Debug("Destroyed listener", zap.String("addr", l.addr))

	return l.SingleStreamListener.Close()
}

type listenerSCION3QUIC struct {
}

func (l *listenerSCION3QUIC) listen(
	ctx context.Context,
	network *Network,
	laddr netip.AddrPort,
	cfg net.ListenConfig,
) (Destructor, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := pan.ListenUDP(ctx, laddr, nil)
	if err != nil {
		return nil, err
	}
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
	_, err := c.network.Pool.Delete(poolKey(SCION3QUIC, c.addr))
	return err
}

// Destruct closes the connection. It is called by the usage pool when the
// reference count goes to zero.
func (c *conn) Destruct() error {
	c.network.Logger().Debug("destroying listener", zap.String("addr", c.addr))
	defer c.network.Logger().Debug("destroyed listener", zap.String("addr", c.addr))

	return c.PacketConn.Close()
}

type listenerSCIONDummy struct {
}

func (l *listenerSCIONDummy) listen(
	ctx context.Context,
	network *Network,
	laddr netip.AddrPort,
	cfg net.ListenConfig,
) (Destructor, error) {
	return &dummyListener{
		address: laddr,
		network: network,
	}, nil
}

// blockedListener is a net.Listener that will never accept a connection. It
// blocks until the underlying connection is closed.
type dummyListener struct {
	address netip.AddrPort
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
	return net.UDPAddrFromAddrPort(l.address)
}

func (l *dummyListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}

func (l *dummyListener) Close() error {
	_, err := l.network.Pool.Delete(poolKey(SCIONDummy, l.address.String()))
	return err
}

func (l *dummyListener) Destruct() error {
	return nil
}

func poolKey(network string, address string) string {
	return fmt.Sprintf("%s:%s", network, address)
}

// parseIPPort parses a string in the format "<ip>:<port>" or ":<port>" into a netip.AddrPort.
// It returns an error if the input string is not in a valid format.
func parseIPPort(s string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("unable to parse IP:Port (%q): %w", s, err)
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port %q in %q: %w", port, s, err)
	}
	if host == "" {
		if _, err := net.DefaultResolver.LookupIPAddr(context.Background(), "::1"); err == nil {
			return netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(port16)), nil
		}
		return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port16)), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid IP address %q in %q: %w", host, s, err)
	}
	return netip.AddrPortFrom(ip, uint16(port16)), nil
}
