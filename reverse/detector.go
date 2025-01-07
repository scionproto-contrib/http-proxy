// Copyright 2024 Anapaya Systems, ETH Zurich
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
	"net/http"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"
)

// Detector is a middleware that adds the X-SCION header to HTTP requests
// if the request is from a SCION-enabled address.
type Detector struct {
	logger *zap.Logger
}

func NewDetector(logger *zap.Logger) *Detector {
	return &Detector{
		logger: logger,
	}
}

func (d *Detector) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if d.logger != nil {
		d.logger.Debug("Checking for SCION traffic.",
			zap.String("remote-address", r.RemoteAddr))
	}
	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err == nil {
		r.Header.Add("X-SCION", "on")
		r.Header.Add("X-SCION-Remote-Addr", r.RemoteAddr)
		// XXX(JordiSubira): This is a workaround to avoid a caddy specific error
		// we should probably move this to a separate middleware.
		remoteAddr, err := pan.ParseUDPAddr(r.RemoteAddr)
		if err != nil {
			d.logger.Debug("Failed to parse remote address", zap.Error(err))
		}
		r.RemoteAddr = remoteAddr.String()
	} else {
		r.Header.Add("X-SCION", "off")
	}
	return nil
}
