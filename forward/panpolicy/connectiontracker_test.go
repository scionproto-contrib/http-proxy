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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddGetRemoveConnection(t *testing.T) {
	ct := connectionTracker{
		conns: make(map[string]map[net.Conn]struct{}),
	}

	// add connection for addr1
	addr1 := "addr1"
	conn1_0 := &testConn{addr1}
	ct.AddConnection(conn1_0, addr1)
	require.Len(t, ct.conns, 1, "connection tracker has wrong number of tracked addresses")
	require.Len(t, ct.conns[addr1], 1, "connection tracker has wrong number of tracked connections for addr %s", addr1)

	addr2 := "addr2"
	conn2_0 := &testConn{addr2}
	// add connection for different addr2
	ct.AddConnection(conn2_0, addr2)
	require.Len(t, ct.conns, 2, "connection tracker has wrong number of tracked addresses")
	require.Len(t, ct.conns[addr1], 1, "connection tracker has wrong number of tracked connections for addr %s", addr1)
	require.Len(t, ct.conns[addr2], 1, "connection tracker has wrong number of tracked connections for addr %s", addr2)

	conn1_1 := &testConn{addr1}
	// add connection for same addr1
	ct.AddConnection(conn1_1, addr1)
	require.Len(t, ct.conns, 2, "connection tracker has wrong number of tracked addresses")
	require.Len(t, ct.conns[addr1], 2, "connection tracker has wrong number of tracked connections for addr %s", addr1)
	require.Len(t, ct.conns[addr2], 1, "connection tracker has wrong number of tracked connections for addr %s", addr2)

	// get conns for both addresses
	conns := ct.GetConnections(addr1)
	require.Len(t, conns, 2, "connection tracker has wrong number of tracked connections for addr %s", addr1)
	conns = ct.GetConnections(addr2)
	require.Len(t, conns, 1, "connection tracker has wrong number of tracked connections for addr %s", addr2)

	// get all conns
	connsPerHost := ct.GetAllConnections()
	require.Len(t, connsPerHost[addr1], 2, "connection tracker has wrong number of tracked connections for addr %s", addr1)
	require.Len(t, connsPerHost[addr2], 1, "connection tracker has wrong number of tracked connections for addr %s", addr2)

	// remove
	ct.RemoveConnection(addr1, conn1_0)
	ct.RemoveConnection(addr2, conn2_0)

	connsPerHost = ct.GetAllConnections()
	require.Len(t, connsPerHost[addr1], 1, "connection tracker has wrong number of tracked connections for addr %s", addr1)
	require.Len(t, connsPerHost[addr2], 0, "connection tracker has wrong number of tracked connections for addr %s", addr2)
}

func TestCloseTrackedConnection(t *testing.T) {
	ct := connectionTracker{
		conns: make(map[string]map[net.Conn]struct{}),
	}

	addr1 := "addr1"
	conn := &testConn{addr1}

	trackedConn := newTrackedConnection(conn, addr1, &ct)

	require.Len(t, ct.conns, 1, "connection tracker has wrong number of tracked addresses")
	require.Len(t, ct.conns[addr1], 1, "connection tracker has wrong number of tracked connections for addr %s", addr1)

	trackedConn.Close()

	conns := ct.GetConnections(addr1)
	require.Len(t, conns, 0, "connection tracker has wrong number of tracked connections for addr %s", addr1)
}

type testConn struct {
	addr string
}

func (c testConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c testConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (c testConn) Close() error                       { return nil }
func (c testConn) LocalAddr() net.Addr                { return nil }
func (c testConn) RemoteAddr() net.Addr               { return nil }
func (c testConn) SetDeadline(t time.Time) error      { return nil }
func (c testConn) SetReadDeadline(t time.Time) error  { return nil }
func (c testConn) SetWriteDeadline(t time.Time) error { return nil }
