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
package singlestream

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/scionproto-contrib/http-proxy/networks"
)

// TestNetwork_Listen tests the Listen method of the Network struct.
func TestNetwork_Listen(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		address   string
		expectErr bool
	}{
		{"Invalid network", "tcp", "[1-ff00:0:110,127.0.0.1]:12345", true},
		{"Valid SCIONSingleStream IPv4 network and address", SCIONSingleStream, "[1-ff00:0:110,127.0.0.1]:12345", false},
		{"Valid SCIONSingleStream any IPv4 network and port", SCIONSingleStream, "[1-ff00:0:110,0.0.0.0]:12345", false},
		{"Valid SCIONSingleStream any IPv6 network and port", SCIONSingleStream, "[1-ff00:0:110,::]:12345", false},
		{"Invalid SCIONSingleStream address", SCIONSingleStream, "invalid-address", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := &Network{
				Pool:     newMockPool[string, networks.Reusable](),
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

type mockReusable struct{}

func (l *mockListener) listen(
	ctx context.Context,
	network *Network,
	laddr *snet.UDPAddr,
	cfg net.ListenConfig,
) (networks.Destructor, error) {
	return &mockReusable{}, nil
}

func (m *mockReusable) Destruct() error {
	return nil
}

func (m *mockReusable) Close() error {
	return nil
}

type mockPool[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]V
}

func newMockPool[K comparable, V any]() *mockPool[K, V] {
	return &mockPool[K, V]{
		entries: make(map[K]V),
	}
}

func (mp *mockPool[K, V]) LoadOrNew(key K, construct func() (networks.Destructor, error)) (V, bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if entry, exists := mp.entries[key]; exists {
		return entry, true, nil
	}

	newEntry, err := construct()
	if err != nil {
		var zero V
		return zero, false, err
	}

	var entry V
	if v, ok := newEntry.(V); ok {
		entry = v
	} else {
		return entry, false, errors.New("type assertion failed")
	}
	mp.entries[key] = entry

	return entry, false, nil
}

func (mp *mockPool[K, V]) Delete(key K) (bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if _, exists := mp.entries[key]; !exists {
		return false, nil
	}

	delete(mp.entries, key)
	return true, nil
}
