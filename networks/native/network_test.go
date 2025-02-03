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
package native

import (
	"context"
	"net"
	"testing"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/scionproto-contrib/http-proxy/networks"
	"github.com/scionproto-contrib/http-proxy/networks/mock"
)

// TestNetwork_Listen tests the Listen method of the Network struct.
func TestNetwork_Listen(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		address   string
		expectErr bool
	}{
		{"Invalid network", SCIONNetwork, "[1-ff00:0:110,127.0.0.1]:12345", true},
		{"Valid SCION+UDP IPv4 network and address", SCIONUDP, "[1-ff00:0:110,127.0.0.1]:12345", false},
		{"Valid SCION+UDP any IPv4 network and port", SCIONUDP, "[1-ff00:0:110,0.0.0.0]:12345", false},
		{"Valid SCION+UDP any IPv6 network and port", SCIONUDP, "[1-ff00:0:110,::]:12345", false},
		{"Invalid SCION+UDP address", SCIONUDP, "invalid-address", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := &Network{
				Pool:     mock.NewPool[string, networks.Reusable](),
				listener: &mockListener{},
			}
			network.SetLogger(zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel)))

			cfg := net.ListenConfig{}
			_, err := network.Listen(context.Background(), tt.network, tt.address, cfg)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockListener struct{}

func (l *mockListener) listen(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	cfg net.ListenConfig,
) (networks.Destructor, error) {
	return &mock.Reusable{}, nil
}
