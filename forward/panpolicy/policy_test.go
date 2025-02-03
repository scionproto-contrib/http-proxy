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
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/scionproto-contrib/http-proxy/forward/session"
)

type policyType int

const (
	acl policyType = iota + 1
	sequence
)

func TestParsePolicy(t *testing.T) {
	cases := map[string]struct {
		policy         []byte
		policyType     policyType
		expectedErr    bool
		expectedPolicy []string
	}{
		"ACL policy only allowing ISD 42": {
			policy:         []byte(`["+ 42", "-"]`),
			policyType:     acl,
			expectedPolicy: []string{"+ 42", "-"},
		},
		"ACL policy deyning ISD 327-99": {
			policy:         []byte(`["- 327-99", "+"]`),
			policyType:     acl,
			expectedPolicy: []string{"- 327-99", "+"},
		},
		"ACL policy allowing all": {
			policy:         []byte(`["+"]`),
			policyType:     acl,
			expectedPolicy: []string{"+"},
		},
		"ACL policy denying all": {
			policy:         []byte(`["-"]`),
			policyType:     acl,
			expectedPolicy: []string{"-"},
		},
		"ACL policy not as array": {
			policy:      []byte(`"+ 42", "-"`),
			policyType:  acl,
			expectedErr: true,
		},
		"ACL policy with no default action": {
			policy:      []byte(`["+ 42"]`),
			policyType:  acl,
			expectedErr: true,
		},
		"sequence policy of two ASes": {
			policy:         []byte(`"42-1 11>20 42-2"`),
			policyType:     sequence,
			expectedPolicy: []string{"42-1 #11 42-2 #20"},
		},
		"sequence policy of three ASes": {
			policy:         []byte(`"42-1 11>20 42-2 21>30 42-3"`),
			policyType:     sequence,
			expectedPolicy: []string{"42-1 #11 42-2 #20,21 42-3 #30"},
		},
		"sequence policy with wild cards": {
			policy:         []byte(`"42-0 0>0 42-0 0>0 42-0"`),
			policyType:     sequence,
			expectedPolicy: []string{"42-0 #0 42-0 #0,0 42-0 #0"},
		},
		"sequence policy of a single AS": {
			policy:      []byte(`"42-0"`),
			policyType:  sequence,
			expectedErr: true,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			parsedPolicy, err := parsePolicy(c.policy)

			if c.expectedErr {
				require.Error(t, err, "expected an error but got none")
				return
			}
			require.NoError(t, err, "unexpected error")

			var p pan.Policy
			switch c.policyType {
			case acl:
				var acl pan.ACL
				acl, err = pan.NewACL(c.expectedPolicy)
				p = &acl
			case sequence:
				p, err = pan.NewSequence(c.expectedPolicy[0])
			default:
				t.Fatalf("invalid policy type %d", c.policyType)
			}
			require.NoError(t, err, "error creating expected policy")

			assert.True(t, reflect.DeepEqual(parsedPolicy, p), "parsed policy does not match expected policy")
		})
	}
}

func TestEnsurePolicyOnDialer(t *testing.T) {
	m := NewPolicyManager(zap.NewNop(), 1*time.Second, true, 0, 0)

	// set new policy
	method := http.MethodPut
	rawPolicy := `["+ 42", "-"]`
	policy := bytes.NewBuffer([]byte(rawPolicy))
	req, err := http.NewRequest(method, "/", policy)
	require.NoError(t, err, "error creating request")

	rr := httptest.NewRecorder()
	err = m.ServeHTTP(rr, req)
	require.NoError(t, err, "error serving HTTP request")

	expectedCode := http.StatusOK
	assert.Equal(t, expectedCode, rr.Code, "handler returned wrong status code")

	// this is an implementation details but the browser extension relies on this
	var sessionCookie *http.Cookie
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == session.SessionName {
			sessionCookie = c
			found = true
			break
		}
	}
	require.True(t, found, "response did not contain a session cookie")

	// check policy is set on dialer
	var p pan.Policy
	require.NotEmpty(t, m.customSDialers.store, "dialer cache did not contain a custom scion dialer")
	for _, s := range m.customSDialers.store {
		p = s.GetPolicy()
		break
	}
	require.NotNil(t, p, "got dialer from dialer cache with no policy set")

	expectedPolicy, err := pan.NewACL([]string{"+ 42", "-"})
	require.NoError(t, err, "error creating expected policy")
	acl, ok := p.(*pan.ACL)
	require.True(t, ok, "policy is not of type ACL")
	assert.True(t, reflect.DeepEqual(acl, &expectedPolicy), "dialer has wrong policy")

	// check policy is set in session
	req, err = http.NewRequest(method, "/", nil)
	require.NoError(t, err, "error creating request")
	req.AddCookie(sessionCookie)

	sessionData, err := session.GetSessionData(m.logger, req)
	require.NoError(t, err, "error getting session data")

	assert.Equal(t, string(sessionData.Policy), rawPolicy, "session has wrong policy")
}

type dialerType int

const (
	std dialerType = iota + 1
	scion
)

func TestGetDialerWithPolicy(t *testing.T) {
	cases := map[string]struct {
		policy             []byte
		useScion           bool
		expectedDialerType dialerType
	}{
		"std dialer": {
			policy:             nil,
			useScion:           false,
			expectedDialerType: std,
		},
		"scion dialer": {
			policy:             nil,
			useScion:           true,
			expectedDialerType: scion,
		},
		"scion dialer with policy": {
			policy:             []byte(`["+ 42", "-"]`),
			useScion:           true,
			expectedDialerType: scion,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewPolicyManager(zap.NewNop(), 1*time.Second, true, 0, 0)
			sd := session.SessionData{ID: "deadbeef", Policy: c.policy}

			d, err := m.GetDialer(sd, c.useScion)
			require.NoError(t, err, "error getting dialer")

			switch c.expectedDialerType {
			case std:
				_, ok := d.(*StdDialer)
				assert.True(t, ok, "get dialer returned wrong dialer type")
			case scion:
				dd, ok := d.(*SCIONDialer)
				require.True(t, ok, "get dialer returned wrong dialer type")

				if c.policy == nil {
					return
				}

				expectedPolicy, err := parsePolicy(c.policy)
				require.NoError(t, err, "error parsing policy")

				assert.True(t, reflect.DeepEqual(dd.GetPolicy(), expectedPolicy), "dialer has wrong policy")
			default:
				t.Fatalf("invalid policy type %d", c.expectedDialerType)
			}

			// querying again with the same session should return the same (logical) dialer
			dd, err := m.GetDialer(sd, c.useScion)
			require.NoError(t, err, "error getting dialer")

			assert.True(t, reflect.DeepEqual(d, dd), "get dialer returned wrong dialer")
		})
	}
}

func TestPurgeAbandonedDialers(t *testing.T) {
	cases := map[string]struct {
		hasConnections    bool
		hasDialedRecently bool
		expectedInMap     bool
	}{
		"dialer with open connections": {
			hasConnections: true,
			expectedInMap:  true,
		},
		"dialer with recent dialation": {
			hasDialedRecently: true,
			expectedInMap:     true,
		},
		"dialer that can be purged": {
			expectedInMap: false,
		},
	}

	id := "deadbeef"
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewPolicyManager(zap.NewNop(), 1*time.Second, true, 0, 0)
			sd := session.SessionData{ID: id}
			d := purgabelDialer{c.hasConnections, c.hasDialedRecently}

			m.customSDialers.Store(sd.ID, d)

			m.purgeAbandonedDialers()

			_, ok := m.customSDialers.Load(id)
			assert.Equal(t, c.expectedInMap, ok, "dialer presence in map does not match expectation")
		})
	}
}

type purgabelDialer struct {
	hasConnections    bool
	hasDialedRecently bool
}

func (p purgabelDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	return nil, nil
}
func (p purgabelDialer) SetPolicy(policy pan.Policy) error                         { return nil }
func (p purgabelDialer) GetPolicy() pan.Policy                                     { return nil }
func (p purgabelDialer) GetMetrics(filteredAddrs []string) (*DialerMetrics, error) { return nil, nil }
func (p purgabelDialer) HasOpenConnections() (bool, error)                         { return p.hasConnections, nil }
func (p purgabelDialer) HasDialedWithinTimeWindow(t time.Duration) (bool, error) {
	return p.hasDialedRecently, nil
}

func TestNewPolicyManager(t *testing.T) {
	logger := zap.NewNop()
	dialTimeout := 1 * time.Second
	purge := true
	purgeTimeout := 5 * time.Minute
	purgeInterval := 10 * time.Minute

	m := NewPolicyManager(logger, dialTimeout, purge, purgeTimeout, purgeInterval)

	assert.NotNil(t, m, "NewPolicyManager returned nil")
	assert.Equal(t, logger, m.logger, "logger does not match")
	assert.Equal(t, dialTimeout, m.dialTimeout, "dialTimeout does not match")
	assert.Equal(t, purge, m.purge, "purge does not match")
	assert.Equal(t, purgeTimeout, m.purgeTimeout, "purgeTimeout does not match")
	assert.Equal(t, purgeInterval, m.purgeInterval, "purgeInterval does not match")
	assert.NotNil(t, m.stdDialer, "stdDialer is nil")
	assert.NotNil(t, m.sharedSDialer, "sharedSDialer is nil")
	assert.NotNil(t, m.customSDialers, "customSDialers is nil")
}

func TestStartAndStopPolicyManager(t *testing.T) {
	logger := zap.NewNop()
	dialTimeout := 1 * time.Second
	purge := true
	purgeTimeout := 5 * time.Minute
	purgeInterval := 10 * time.Minute

	m := NewPolicyManager(logger, dialTimeout, purge, purgeTimeout, purgeInterval)

	err := m.Start()
	require.NoError(t, err, "error starting policy manager")

	assert.NotNil(t, m.purgeTicker, "purgeTicker is nil after starting")

	err = m.Stop()
	require.NoError(t, err, "error stopping policy manager")
}
