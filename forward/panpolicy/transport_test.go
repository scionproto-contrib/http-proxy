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
	"testing"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSetPolicy(t *testing.T) {
	cases := map[string]struct {
		oldPolicy pan.Policy
		policy    *pan.ACL
		cleared   bool
	}{
		"set first policy": {
			oldPolicy: nil,
			policy:    MustParseACL(t, "+ 42", "-"),
			cleared:   true,
		},
		"set new policy": {
			oldPolicy: MustParseACL(t, "+ 27", "-"),
			policy:    MustParseACL(t, "+ 42", "-"),
			cleared:   true,
		},
		"set same policy": {
			oldPolicy: MustParseACL(t, "+ 42", "-"),
			policy:    MustParseACL(t, "+ 42", "-"),
			cleared:   false,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fmt.Println(name)
			// given
			d := NewSCIONDialer(zap.NewNop(), 1*time.Second, false)
			d.lastUsedPathForAddr = map[string]*pathInfo{"dummy": nil}
			t.Logf("%v", d.lastUsedPathForAddr)
			t.Log(len(d.lastUsedPathForAddr))
			err := d.dialSCION.SetPolicy(c.oldPolicy)
			require.NoError(t, err)

			// when
			expectedPolicy := c.policy
			err = d.SetPolicy(expectedPolicy)
			require.NoError(t, err)

			// then
			actualPolicy := d.dialSCION.GetPolicy()
			var ok bool
			var actualACL *pan.ACL
			actualACL, ok = actualPolicy.(*pan.ACL)
			require.True(t, ok, "dialer policy has wrong data type: got %T, want *pan.ACL", actualPolicy)
			assert.Equal(t, expectedPolicy.String(), actualACL.String(), "dialer policy is wrong")
			assert.Equal(t, c.cleared, len(d.lastUsedPathForAddr) == 0, "dialer has inconsistent state")
		})
	}
}

func TestDialContext(t *testing.T) {
	d := NewSCIONDialer(zap.NewNop(), 1*time.Second, true)
	checker := &checkDialer{}
	d.dialSCION = checker

	addr := "17-ffaa:1:1103,[1.2.3.4]"
	_, _ = d.DialContext(context.Background(), "", addr)

	assert.True(t, checker.dialCalled, "scion dialer did not call underlying dialer")

	conns := d.connectionTracker.GetConnections(addr)
	assert.Equal(t, 1, len(conns), "connection tracker has wrong number of tracked connections for addr %s", addr)
}

type checkDialer struct{ dialCalled bool }

func (d *checkDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	d.dialCalled = true
	return &noopConn{}, nil
}
func (d checkDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) { return nil, nil }
func (d checkDialer) SetPolicy(policy pan.Policy) error                         { return nil }
func (d checkDialer) GetPolicy() pan.Policy                                     { return nil }
func (d checkDialer) HasOpenConnections() (bool, error)                         { return true, nil }
func (d checkDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error)   { return true, nil }

func TestGetMetrics(t *testing.T) {
	addr1 := "addr1"
	addr2 := "addr2"
	pathA := &pan.Path{Source: pan.MustParseIA("42-0")}
	pathB := &pan.Path{Source: pan.MustParseIA("42-3")}
	emptyIA := pan.IA(0)

	cases := map[string]struct {
		conns         map[string][]pathAwareConn
		lastPath      map[string]*pathInfo
		filter        []string
		expectedErr   bool
		expectedPaths []*ConnInfo
	}{
		"no connections at all": {
			conns:       nil,
			expectedErr: true,
		},
		"no connections for addr": {
			conns: map[string][]pathAwareConn{
				addr1: nil,
			},
			expectedErr: true,
		},
		"no connections for addr but last path available": {
			conns: map[string][]pathAwareConn{
				addr1: {},
			},
			lastPath: map[string]*pathInfo{
				addr1: {pathA, emptyIA},
			},
			expectedPaths: []*ConnInfo{
				{Addr: addr1, PathInfo: &pathInfo{pathA, emptyIA}},
			},
		},
		"single connection for single addr": {
			conns: map[string][]pathAwareConn{
				addr1: {
					noopConn{path: pathA},
				},
			},
			expectedPaths: []*ConnInfo{
				{Addr: addr1, PathInfo: &pathInfo{pathA, emptyIA}},
			},
		},
		"multiple connectionss for single addr": {
			conns: map[string][]pathAwareConn{
				addr1: {
					noopConn{path: pathA},
					noopConn{path: pathA},
				},
			},
			expectedPaths: []*ConnInfo{
				{Addr: addr1, PathInfo: &pathInfo{pathA, emptyIA}},
			},
		},
		"single connection for multiple addr": {
			conns: map[string][]pathAwareConn{
				addr1: {
					noopConn{path: pathA},
				},
				addr2: {
					noopConn{path: pathB},
				},
			},
			expectedPaths: []*ConnInfo{
				{Addr: addr1, PathInfo: &pathInfo{pathA, emptyIA}},
				{Addr: addr2, PathInfo: &pathInfo{pathB, emptyIA}},
			},
		},
		"filter addresses": {
			conns: map[string][]pathAwareConn{
				addr1: {
					noopConn{path: pathA},
				},
				addr2: {
					noopConn{path: pathB},
				},
			},
			filter: []string{addr2},
			expectedPaths: []*ConnInfo{
				{Addr: addr2, PathInfo: &pathInfo{pathB, emptyIA}},
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fmt.Println(name)
			d := NewSCIONDialer(zap.NewNop(), 1*time.Second, false)
			d.lastUsedPathForAddr = c.lastPath
			for addr, ac := range c.conns {
				if ac != nil && len(ac) == 0 {
					// HACK to simulate added and later closed connection
					d.connectionTracker.conns[addr] = nil
				}
				for _, panconn := range ac {
					d.connectionTracker.AddConnection(panconn, addr)
				}
			}

			m, err := d.GetMetrics(c.filter)
			if c.expectedErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			paths := m.connInfo

			s := strings.Builder{}
			s.Write([]byte("\ngot:"))
			for _, p := range paths {
				s.Write([]byte(fmt.Sprintf(" %v %v", p.Addr, p.PathInfo)))
			}
			s.Write([]byte("\nwant:"))
			for _, p := range c.expectedPaths {
				s.Write([]byte(fmt.Sprintf(" %v %v", p.Addr, p.PathInfo)))
			}

			assert.Equal(t, len(c.expectedPaths), len(paths), "get path returned wrong number of paths\n%s", s.String())
			for _, ep := range c.expectedPaths {
				found := false
				for _, p := range paths {
					if reflect.DeepEqual(ep, p) {
						found = true
						break
					}
				}
				assert.True(t, found, "get path returned wrong paths\n%s", s.String())
			}
		})
	}
}

var _ pathAwareConn = (*noopConn)(nil)

type noopConn struct {
	net.Conn
	ia   pan.IA
	path *pan.Path
}

func (c noopConn) GetPath() *pan.Path  { return c.path }
func (c noopConn) LocalAddr() net.Addr { return pan.UDPAddr{IA: c.ia} }

func TestSharedDialerCannotHavePolicy(t *testing.T) {
	d := NewSCIONDialer(zap.NewNop(), 1*time.Second, true)
	acl, err := pan.NewACL([]string{"+ 42", "-"})
	require.NoError(t, err)

	policy := &acl
	err = d.SetPolicy(policy)
	assert.ErrorIs(t, err, ErrInvalidOperation, "set policy on a shared dialer should give an error")

	require.NoError(t, d.dialSCION.SetPolicy(policy)) // set policy directly on internal dialer

	p := d.GetPolicy()
	assert.Nil(t, p, "get policy on shared dialer should give empty result")
}

func TestSharedDialerDoesNotLeakMetrics(t *testing.T) {
	t.Skip("Skipping until we now if we want that or not")

	d := NewSCIONDialer(zap.NewNop(), 1*time.Second, true)
	d.dialSCION = &metricsDialer{}

	metrics, err := d.GetMetrics(nil)
	require.NoError(t, err)
	assert.Empty(t, metrics.connInfo, "shared dialer should not leak path metrics")
}

type metricsDialer struct{}

func (d *metricsDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return &noopConn{}, nil
}
func (d metricsDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) {
	return &DialerMetrics{
		nil, []*ConnInfo{{Addr: "foo.bar", PathInfo: nil}},
	}, nil
}
func (d metricsDialer) SetPolicy(policy pan.Policy) error                       { return nil }
func (d metricsDialer) GetPolicy() pan.Policy                                   { return nil }
func (d metricsDialer) HasOpenConnections() (bool, error)                       { return true, nil }
func (d metricsDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error) { return true, nil }
