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

package panpolicy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/scionassociation/http-scion/forward/session"
)

func TestMetricsHandler(t *testing.T) {
	cases := map[string]struct {
		policy       pan.Policy
		connInfos    []*ConnInfo
		expectedBody string
	}{
		"no connection": {
			connInfos:    []*ConnInfo{},
			expectedBody: `[]`,
		},
		"request within same IA": {
			connInfos: []*ConnInfo{
				{Addr: "addr1", PathInfo: &pathInfo{nil, pan.MustParseIA("42-0")}},
			},
			expectedBody: `[{"Domain":"addr1","Path":["42-0"],"Strategy":"Shortest Path (AS hops)"}]`,
		},
		"request across IAs": {
			connInfos: []*ConnInfo{
				{
					Addr: "addr1",
					PathInfo: &pathInfo{
						&pan.Path{
							Source:      pan.MustParseIA("42-1"),
							Destination: pan.MustParseIA("42-3"),
							Metadata: &pan.PathMetadata{
								Interfaces: []pan.PathInterface{
									{IA: pan.MustParseIA("42-1"), IfID: pan.IfID(19)},
									{IA: pan.MustParseIA("42-2"), IfID: pan.IfID(20)},
									{IA: pan.MustParseIA("42-2"), IfID: pan.IfID(29)},
									{IA: pan.MustParseIA("42-3"), IfID: pan.IfID(30)},
								},
							},
						},
						pan.MustParseIA("42-0"),
					},
				},
			},
			expectedBody: `[{"Domain":"addr1","Path":["42-1","42-2","42-3"],"Strategy":"Shortest Path (AS hops)"}]`,
		},
		"request with some policy": {
			policy: MustParseACL(t, "+"),
			connInfos: []*ConnInfo{
				{Addr: "addr1", PathInfo: &pathInfo{nil, pan.MustParseIA("42-0")}},
			},
			expectedBody: `[{"Domain":"addr1","Path":["42-0"],"Strategy":"Geofenced"}]`,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			metricsHandler := NewMetricsHandler(
				mockDialerPool{
					dialer: mockDialer{
						policy:    c.policy,
						connInfos: c.connInfos,
					},
				},
				zap.NewNop(),
			)

			method := http.MethodPut
			req, err := http.NewRequest(method, "/", nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			metricsHandler.ServeHTTP(rr, req)
			require.NoError(t, err)

			expectedCode := http.StatusOK
			assert.Equal(t, expectedCode, rr.Code, "handler returned wrong status code")

			assert.Equal(t, c.expectedBody, strings.TrimSpace(rr.Body.String()), "handler returned unexpected body")
		})
	}
}

type mockDialerPool struct {
	dialer mockDialer
}

func (dp mockDialerPool) Start() error { return nil }
func (dp mockDialerPool) Stop() error  { return nil }

func (dp mockDialerPool) GetDialer(sessionData session.SessionData, useScion bool) (PANDialer, error) {
	return dp.dialer, nil
}
func (dp mockDialerPool) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type mockDialer struct {
	policy    pan.Policy
	connInfos []*ConnInfo
}

func (d mockDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) {
	if len(d.connInfos) == 0 {
		return nil, ErrNoConnections
	}
	return &DialerMetrics{
		d.policy, d.connInfos,
	}, nil
}
func (d mockDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return nil, nil
}
func (d mockDialer) SetPolicy(policy pan.Policy) error                       { return nil }
func (d mockDialer) GetPolicy() pan.Policy                                   { return nil }
func (d mockDialer) HasOpenConnections() (bool, error)                       { return true, nil }
func (d mockDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error) { return true, nil }

func MustParseACL(t *testing.T, policy ...string) *pan.ACL {
	acl, err := pan.NewACL(policy)
	require.NoError(t, err)
	return &acl
}
