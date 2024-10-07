// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package panpolicy

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ PANDialer = (*SCIONDialer)(nil)
	_ PANDialer = (*StdDialer)(nil)
	_ PANDialer = (*internalSCIONDialer)(nil)

	_ pathAwareConn = (*quicutil.SingleStream)(nil)
)

type SCIONDialer struct {
	dialSCION   PANDialer
	dialTimeout time.Duration

	connectionTracker   *connectionTracker
	lastUsedPathForAddr map[string]*pathInfo

	lastDial *time.Time

	shared bool

	logger *zap.Logger
}

type pathInfo struct {
	path  *pan.Path
	local pan.IA
}

type pathAwareConn interface {
	net.Conn
	GetPath() *pan.Path
	LocalAddr() net.Addr
}

func NewSCIONDialer(logger *zap.Logger, dialTimeout time.Duration, shared bool) *SCIONDialer {
	return &SCIONDialer{
		dialSCION:   &internalSCIONDialer{dialer: &shttp.Dialer{}},
		dialTimeout: dialTimeout,
		connectionTracker: &connectionTracker{
			conns: make(map[string]map[net.Conn]struct{}),
		},
		lastUsedPathForAddr: make(map[string]*pathInfo),
		shared:              shared,
		logger:              logger,
	}
}

var ErrDialTimeout = fmt.Errorf("dial timeout")

func (d *SCIONDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	log := d.logger.With(zap.String("network", network), zap.String("addr", addr))

	s := ""
	policy := d.dialSCION.GetPolicy()
	if seq, ok := policy.(pan.Sequence); ok {
		s = seq.String()
	}
	if acl, ok := policy.(*pan.ACL); ok {
		s = acl.String()
	}
	log.Debug("Dialing new connection.", zap.String("path-policy", s))

	ctxTimeout, cancel := context.WithTimeout(ctx, d.dialTimeout)
	defer cancel()

	connc, errc := make(chan net.Conn, 1), make(chan error, 1)
	go func() {
		conn, err := d.dialSCION.DialContext(ctxTimeout, network, addr)
		if err != nil {
			errc <- err
			return
		}
		connc <- conn
	}()

	select {
	case <-ctxTimeout.Done():
		return nil, ErrDialTimeout
	case err := <-errc:
		return nil, err
	case conn := <-connc:
		if panConn, ok := conn.(pathAwareConn); ok {
			conn = newTrackedConnection(panConn, addr, d.connectionTracker)

			var ia pan.IA
			if addr, ok := panConn.LocalAddr().(pan.UDPAddr); ok {
				ia = addr.IA
			}

			pi := &pathInfo{panConn.GetPath(), ia}
			d.lastUsedPathForAddr[addr] = pi
			log.Debug("Using path.",
				zap.String("addr", addr),
				zap.String("path", strings.Join(hopsToPathHops(pi), ",")))

		}

		t := time.Now()
		d.lastDial = &t

		return conn, nil
	}
}

var ErrNoConnections = fmt.Errorf("dialer has no open connections")

type DialerMetrics struct {
	policy   pan.Policy
	connInfo []*ConnInfo
}

type ConnInfo struct {
	Addr     string
	PathInfo *pathInfo
}

func (d *SCIONDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) {
	if d.shared {
		// wont share any paths for the shared dialer
		// TODO maybe we want?
		return &DialerMetrics{}, nil
	}

	panConnsPerAddr := d.connectionTracker.GetAllConnections()
	if len(panConnsPerAddr) == 0 {
		return nil, ErrNoConnections
	}

	if len(filteredAddrs) != 0 {
		for addr := range panConnsPerAddr {
			found := false
			for _, f := range filteredAddrs {
				if addr == f {
					found = true
					break
				}
			}
			if !found {
				delete(panConnsPerAddr, addr)
			}
		}
	}

	var connInfos []*ConnInfo
	for addr, conns := range panConnsPerAddr {
		if len(conns) == 0 {
			// no open connection, checking for last used
			if lastUsedPath, ok := d.lastUsedPathForAddr[addr]; ok {
				connInfos = append(connInfos, &ConnInfo{
					Addr:     addr,
					PathInfo: lastUsedPath,
				})
			}
			continue
		}

		var ok bool
		var panConn pathAwareConn
		conn := conns[0]
		if panConn, ok = conn.(pathAwareConn); !ok {
			return nil, fmt.Errorf("tracked connection is of invalid type")
		}

		var ia pan.IA
		if addr, ok := panConn.LocalAddr().(pan.UDPAddr); ok {
			ia = addr.IA
		}

		path := panConn.GetPath()
		connInfos = append(connInfos, &ConnInfo{
			Addr:     addr,
			PathInfo: &pathInfo{path, ia},
		})

		for i, conn := range conns {
			if panConn, ok = conn.(pathAwareConn); !ok {
				return nil, fmt.Errorf("tracked connection is of invalid type")
			}

			if i != 0 && !reflect.DeepEqual(path, panConn.GetPath()) {
				d.logger.Warn("Some connections have different paths.",
					zap.String("addr", addr),
					zap.String("some", path.String()),
					zap.String("other", panConn.GetPath().String()))
			}
		}
	}

	dm := &DialerMetrics{
		connInfo: connInfos,
	}
	if !d.shared {
		dm.policy = d.dialSCION.GetPolicy()
	}

	return dm, nil
}

var ErrInvalidOperation = fmt.Errorf("invalid operation on dialer")

func (d *SCIONDialer) SetPolicy(policy pan.Policy) error {
	if d.shared {
		// cant set a policy on the shared dialer
		return ErrInvalidOperation
	}

	if !reflect.DeepEqual(d.dialSCION.GetPolicy(), policy) {
		// clear cached paths, to avoid inconsistenies
		d.lastUsedPathForAddr = make(map[string]*pathInfo)
	}
	return d.dialSCION.SetPolicy(policy)
}

func (d *SCIONDialer) GetPolicy() pan.Policy {
	if d.shared {
		// shared dialer has no policy
		return nil
	}

	return d.dialSCION.GetPolicy()
}

func (d *SCIONDialer) HasOpenConnections() (bool, error) {
	for _, cs := range d.connectionTracker.GetAllConnections() {
		if len(cs) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (d *SCIONDialer) HasDialedWithinTimeWindow(window time.Duration) (bool, error) {
	return d.lastDial != nil && time.Since(*d.lastDial) < window, nil
}

// internalSCIONDialer wraps shttp.Dialer and implement a usable interface (required for testing)
type internalSCIONDialer struct {
	dialer *shttp.Dialer
}

func (d internalSCIONDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d internalSCIONDialer) SetPolicy(policy pan.Policy) error {
	d.dialer.SetPolicy(policy)
	return nil
}

func (d internalSCIONDialer) GetPolicy() pan.Policy { return d.dialer.Policy }

func (d internalSCIONDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) {
	return nil, fmt.Errorf("operation not supported")
}

func (d internalSCIONDialer) HasOpenConnections() (bool, error) {
	return false, fmt.Errorf("operation not supported")
}

func (d internalSCIONDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error) {
	return false, fmt.Errorf("operation not supported")
}

var ErrOperationNotSupported = fmt.Errorf("not a scion dialer")

type StdDialer struct {
	dialer *net.Dialer
}

func NewStdDialer(logger *zap.Logger, dialTimeout time.Duration) *StdDialer {
	return &StdDialer{
		dialer: &net.Dialer{
			Timeout: dialTimeout,
		},
	}
}

func (d *StdDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *StdDialer) SetPolicy(policy pan.Policy) error {
	return ErrOperationNotSupported
}

func (d *StdDialer) GetPolicy() pan.Policy {
	return nil
}

func (p *StdDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) {
	return nil, ErrOperationNotSupported
}

func (p *StdDialer) HasOpenConnections() (bool, error) {
	return true, nil
}

func (p *StdDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error) {
	return true, nil
}

type connectionTracker struct {
	connsMu sync.RWMutex
	conns   map[string]map[net.Conn]struct{}
}

// AddConnection add a connection in the tracked connections list.
func (c *connectionTracker) AddConnection(conn net.Conn, addr string) {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	conns := c.conns[addr]
	if conns == nil {
		conns = make(map[net.Conn]struct{})
	}
	conns[conn] = struct{}{}
	c.conns[addr] = conns
}

// RemoveConnection remove a connection from the tracked connections list.
func (c *connectionTracker) RemoveConnection(addr string, conn net.Conn) {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	conns := c.conns[addr]
	delete(conns, conn)
}

func (c *connectionTracker) GetConnections(addr string) []net.Conn {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	if len(c.conns[addr]) == 0 {
		return []net.Conn{}
	}

	conns := make([]net.Conn, len(c.conns[addr]))

	i := 0
	for k := range c.conns[addr] {
		conns[i] = k
		i++
	}

	return conns
}

func (c *connectionTracker) GetAllConnections() map[string][]net.Conn {
	connsPerAddr := make(map[string][]net.Conn, len(c.conns))

	for addr, c := range c.conns {
		var conns []net.Conn
		for cc := range c {
			conns = append(conns, cc)
		}
		connsPerAddr[addr] = conns
	}

	return connsPerAddr
}

var _ net.Conn = (*trackedConnection)(nil)

type trackedConnection struct {
	tracker *connectionTracker
	addr    string
	net.Conn
}

func newTrackedConnection(conn net.Conn, addr string, tracker *connectionTracker) *trackedConnection {
	tracker.AddConnection(conn, addr)
	return &trackedConnection{
		tracker: tracker,
		addr:    addr,
		Conn:    conn,
	}
}

func (c *trackedConnection) Close() error {
	c.tracker.RemoveConnection(c.addr, c.Conn)
	return c.Conn.Close()
}
