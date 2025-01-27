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

	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"
)

// Advertiser is a middleware that adds the Strict-SCION header to HTTP responses
// if the request is not from a SCION-enabled address.
type Advertiser struct {
	StrictScion string
	logger      *zap.Logger
}

func NewAdvertiser(logger *zap.Logger, strictScion string) *Advertiser {
	return &Advertiser{
		StrictScion: strictScion,
		logger:      logger,
	}
}

func (a *Advertiser) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if a.logger != nil {
		a.logger.Debug("Checking for SCION traffic.",
			zap.String("remote-address", r.RemoteAddr))
	}

	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err != nil {
		if w.Header().Get("Strict-SCION") == "" {
			w.Header().Set("Strict-SCION", a.StrictScion)
		}
	}
	return nil
}
