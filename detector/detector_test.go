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
package detector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDetector_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		expectedHeader string
		expectedValue  string
	}{
		{
			name:           "Valid SCION address",
			remoteAddr:     "1-ff00:0:110,[127.0.0.1]:12345",
			expectedHeader: "X-SCION",
			expectedValue:  "on",
		},
		{
			name:           "Invalid SCION address",
			remoteAddr:     "127.0.0.1:12345",
			expectedHeader: "X-SCION",
			expectedValue:  "off",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			rr := httptest.NewRecorder()

			detector := Detector{
				logger: zap.NewNop(),
			}

			err := detector.ServeHTTP(rr, req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedValue, req.Header.Get(tt.expectedHeader))
			if tt.expectedValue == "on" {
				assert.Equal(t, tt.remoteAddr, req.Header.Get("X-SCION-Remote-Addr"))
			}
		})
	}
}
