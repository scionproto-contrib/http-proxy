package reverseproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type MockQUICListener struct{}

func (l *MockQUICListener) Listen(ctx context.Context, local netip.AddrPort, selector pan.ReplySelector,
	tlsConf *tls.Config, quicConfig *quic.Config) (*quic.Listener, error) {
	return nil, nil
}

func TestNetwork_ListenSCION(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		address   string
		expectErr bool
	}{
		{
			name:      "Valid SCION network and address",
			network:   scionNetwork,
			address:   "127.0.0.100:12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION network and port",
			network:   scionNetwork,
			address:   ":12345",
			expectErr: false,
		},
		{
			name:      "Valid SCION network and no address",
			network:   scionNetwork,
			address:   "",
			expectErr: false,
		},
		{
			name:      "Invalid network",
			network:   "tcp",
			address:   "127.0.0.100:12345",
			expectErr: true,
		},
		{
			name:      "Invalid SCION address",
			network:   scionNetwork,
			address:   "invalid-address",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				scionPool:    NewUsagePool[string, *listener](),
				QUICListener: &MockQUICListener{},
			}
			n.SetLogger(zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel)))

			cfg := net.ListenConfig{}
			_, err := n.ListenSCION(context.Background(), tt.network, tt.address, cfg)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
