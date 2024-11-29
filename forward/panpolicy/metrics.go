// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package panpolicy

import (
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/scionassociation/http-proxy/forward/session"
	"github.com/scionassociation/http-proxy/forward/utils"
)

type strategyType string

const (
	shortestPath strategyType = "Shortest Path (AS hops)"
	geofenced    strategyType = "Geofenced"
)

type MetricsHandler struct {
	policyManager DialerManager

	logger *zap.Logger
}

func NewMetricsHandler(policyManager DialerManager, logger *zap.Logger) *MetricsHandler {
	return &MetricsHandler{
		policyManager: policyManager,
		logger:        logger,
	}
}

// TODO maybe we should key this with the address (instead of it being a member)
type pathMetrics struct {
	Addr     string
	PathInfo *pathInfo
	Strategy strategyType
}

// MarshalJSON marshals the pathMetrics in the format the browser extension expects it
func (p *pathMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Addr     string   `json:"Domain"`
		Path     []string `json:"Path"`
		Strategy string   `json:"Strategy"`
	}{
		Addr:     p.Addr,
		Path:     hopsToPathHops(p.PathInfo),
		Strategy: string(p.Strategy),
	})
}

func (p *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	data, err := p.getMetrics(r)
	if err != nil {
		return utils.NewHandlerError(http.StatusInternalServerError, err)
	}

	j, err := json.Marshal(data)
	if err != nil {
		return utils.NewHandlerError(http.StatusInternalServerError, err)
	}

	_, err = w.Write(j)
	if err != nil {
		return utils.NewHandlerError(http.StatusInternalServerError, err)
	}

	return nil
}

func (p *MetricsHandler) getMetrics(r *http.Request) ([]*pathMetrics, error) {
	sessionData, err := session.GetSessionData(p.logger, r)
	if err != nil {
		return nil, err
	}

	dialer, err := p.policyManager.GetDialer(sessionData, true)
	if err != nil {
		return nil, err
	}

	metrics, err := dialer.GetMetrics(nil)
	if err != nil {
		if errors.Is(err, ErrNoConnections) {
			// handle ErrNoConnections gracefully
			return []*pathMetrics{}, nil
		}
		return nil, err
	}

	strategy := shortestPath
	if metrics.policy != nil {
		strategy = geofenced
	}

	pms := make([]*pathMetrics, len(metrics.connInfo))
	for i, ci := range metrics.connInfo {
		pms[i] = &pathMetrics{
			Addr:     ci.Addr,
			PathInfo: ci.PathInfo,
			Strategy: strategy,
		}
	}

	return pms, nil
}

func hopsToPathHops(pathInfo *pathInfo) []string {
	if pathInfo == nil {
		return []string{}
	}

	path := pathInfo.path
	if path == nil {
		return []string{pathInfo.local.String()}
	}
	if path.Metadata == nil || len(path.Metadata.Interfaces) == 0 {
		return []string{}
	}

	hops := []string{}
	hops = append(hops, path.Source.String())
	for i := 1; i < len(path.Metadata.Interfaces)-1; i += 2 {
		intf := path.Metadata.Interfaces[i]
		hops = append(hops, intf.IA.String())
	}
	hops = append(hops, path.Destination.String())

	return hops
}
