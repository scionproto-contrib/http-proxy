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
package advertiser

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestAdvertiser_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		strictScion    string
		expectedHeader string
	}{
		{
			name:           "Valid SCION address",
			remoteAddr:     "1-ff00:0:110,[192.0.2.1]:12345",
			strictScion:    "1-ff00:0:110,[192.0.2.1]:12345",
			expectedHeader: "",
		},
		{
			name:           "Invalid SCION address",
			remoteAddr:     "192.0.2.1:12345",
			strictScion:    "1-ff00:0:110,[192.0.2.1]:12345",
			expectedHeader: "1-ff00:0:110,[192.0.2.1]:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := Advertiser{
				StrictScion: tt.strictScion,
				logger:      zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel)),
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()

			err := handler.ServeHTTP(rec, req)
			assert.NoError(t, err)

			if tt.expectedHeader == "" {
				assert.Empty(t, rec.Header().Get("Strict-SCION"))
			} else {
				assert.Equal(t, tt.expectedHeader, rec.Header().Get("Strict-SCION"))
			}
		})
	}
}
