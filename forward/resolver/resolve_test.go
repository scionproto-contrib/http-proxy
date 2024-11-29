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
package resolver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto-contrib/http-proxy/forward/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type MockResolver struct {
	addr pan.UDPAddr
}

func (r MockResolver) Resolve(ctx context.Context, name string) (pan.UDPAddr, error) {
	if r.addr == (pan.UDPAddr{}) {
		// non-resolvable
		return pan.UDPAddr{}, nil
	}
	return r.addr, nil
}

func TestHandleHostResolutionRequest(t *testing.T) {
	cases := map[string]struct {
		method       string
		hosts        []string
		addr         pan.UDPAddr
		expectedCode int
		expectedBody string
	}{
		"no host":        {http.MethodGet, []string{}, pan.UDPAddr{}, http.StatusBadRequest, ""},
		"happy case":     {http.MethodGet, []string{"host1"}, mustParse("42-beef:0:0,1.2.3.4:1234"), http.StatusOK, "42-beef:0:0,1.2.3.4:1234"},
		"too many hosts": {http.MethodGet, []string{"host1", "host2"}, pan.UDPAddr{}, http.StatusBadRequest, ""},
		"HEAD request":   {http.MethodHead, []string{"host1"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
		"POST request":   {http.MethodPost, []string{"host1"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
		"PUT request":    {http.MethodPut, []string{"host1"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
		"empty response": {http.MethodGet, []string{"host1"}, pan.UDPAddr{}, http.StatusOK, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			hostResolver := ScionHostResolver{
				resolver: MockResolver{addr: c.addr},
				logger:   zap.NewNop(),
			}

			params := strings.Builder{}
			for i, h := range c.hosts {
				if i == 0 {
					params.WriteString("?")
				} else {
					params.WriteString("&")
				}
				params.WriteString(fmt.Sprintf("host=%s", h))
			}
			req, err := http.NewRequest(c.method, "/"+params.String(), nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			err = hostResolver.HandleHostResolutionRequest(rr, req)

			var status int
			if err != nil {
				require.IsType(t, &utils.HandlerError{}, err)
				he := err.(*utils.HandlerError)
				status = he.StatusCode
			} else {
				status = rr.Code
			}

			assert.Equal(t, c.expectedCode, status, "handler returned wrong status code")

			assert.Equal(t, c.expectedBody, rr.Body.String(), "handler returned unexpected body")
		})
	}
}

func TestHandleRedirectBackOrError(t *testing.T) {
	cases := map[string]struct {
		method           string
		urls             []string
		addr             pan.UDPAddr
		expectedCode     int
		expectedLocation string
	}{
		"no URL":         {http.MethodGet, []string{}, pan.UDPAddr{}, http.StatusBadRequest, ""},
		"happy case":     {http.MethodGet, []string{"http://resolve.me"}, mustParse("42-beef:0:0,1.2.3.4:1234"), http.StatusMovedPermanently, "http://resolve.me"},
		"to many URLs":   {http.MethodGet, []string{"http://resolve.me", "http://resolve.me.too"}, pan.UDPAddr{}, http.StatusBadRequest, ""},
		"non-resolvable": {http.MethodGet, []string{"http://resolve.me"}, pan.UDPAddr{}, http.StatusServiceUnavailable, ""},
		"HEAD request":   {http.MethodHead, []string{"http://resolve.me"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
		"POST request":   {http.MethodPost, []string{"http://resolve.me"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
		"PUT request":    {http.MethodPut, []string{"http://resolve.me"}, pan.UDPAddr{}, http.StatusMethodNotAllowed, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			hostResolver := ScionHostResolver{
				resolver: MockResolver{addr: c.addr},
				logger:   zap.NewNop(),
			}

			params := strings.Builder{}
			for i, h := range c.urls {
				if i == 0 {
					params.WriteString("?")
				} else {
					params.WriteString("&")
				}
				params.WriteString(fmt.Sprintf("url=%s", h))
			}
			req, err := http.NewRequest(c.method, "/"+params.String(), nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			err = hostResolver.HandleRedirectBackOrError(rr, req)

			var status int
			if err != nil {
				require.IsType(t, &utils.HandlerError{}, err)
				he := err.(*utils.HandlerError)
				status = he.StatusCode
			} else {
				status = rr.Code
			}

			assert.Equal(t, c.expectedCode, status, "handler returned wrong status code")

			assert.Equal(t, c.expectedLocation, rr.Header().Get("Location"), "handler returned unexpected redirection location")
		})
	}
}

func mustParse(addr string) pan.UDPAddr {
	a, err := pan.ParseUDPAddr(addr)
	if err != nil {
		panic(fmt.Sprintf("test input must parse %s", err))
	}
	return a
}
