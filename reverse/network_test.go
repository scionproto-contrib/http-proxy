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
package reverse

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestNetwork_Listen(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		address   string
		expectErr bool
	}{
		{
			name:      "Invalid network",
			network:   "tcp",
			address:   "127.0.0.100:12345",
			expectErr: true,
		},
		{
			name:      "Valid SCION network and address",
			network:   SCION,
			address:   "127.0.0.100:12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION network and port",
			network:   SCION,
			address:   ":12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION network and no address",
			network:   SCION,
			address:   "",
			expectErr: true,
		},
		{
			name:      "Invalid SCION address",
			network:   SCION,
			address:   "invalid-address",
			expectErr: true,
		},
		{
			name:      "Valid SCION3 network and address",
			network:   SCION3,
			address:   "127.0.0.100:12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION3 network and port",
			network:   SCION3,
			address:   ":12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION3 network and no address",
			network:   SCION3,
			address:   "",
			expectErr: true,
		},
		{
			name:      "Invalid SCION3 address",
			network:   SCION3,
			address:   "invalid-address",
			expectErr: true,
		},
		{
			name:      "Valid SCION3QUIC network and address",
			network:   SCION3QUIC,
			address:   "127.0.0.100:12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION3QUIC network and port",
			network:   SCION3QUIC,
			address:   ":12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION3QUIC network and no address",
			network:   SCION3QUIC,
			address:   "",
			expectErr: true,
		},
		{
			name:      "Invalid SCION3QUIC address",
			network:   SCION3QUIC,
			address:   "invalid-address",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				Pool:               newMockPool[string, Reusable](),
				listenerSCION:      &mockQUICListener{},
				listenerSCION3QUIC: &mockQUICListener{},
				listenerSCIONDummy: &mockQUICListener{},
			}
			n.SetLogger(zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel)))

			cfg := net.ListenConfig{}
			_, err := n.Listen(context.Background(), tt.network, tt.address, cfg)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockQUICListener struct{}

type mockReusable struct{}

func (l *mockQUICListener) listen(
	ctx context.Context,
	network *Network,
	laddr netip.AddrPort,
	cfg net.ListenConfig,
) (Destructor, error) {
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

func (mp *mockPool[K, V]) LoadOrNew(key K, construct func() (Destructor, error)) (V, bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Check if the entry already exists
	if entry, exists := mp.entries[key]; exists {
		return entry, true, nil
	}

	// Create a new entry
	newEntry, err := construct()
	if err != nil {
		var zero V
		return zero, false, err
	}

	// Store the new entry
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

	// Check if the entry exists
	if _, exists := mp.entries[key]; !exists {
		return false, nil
	}

	// Delete the entry
	delete(mp.entries, key)
	return true, nil
}
