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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionassociation/http-scion/forward/utils"
	"go.uber.org/zap"
)

type ScionHostResolver struct {
	resolver Resolver
	logger   *zap.Logger
}

func NewScionHostResolver(logger *zap.Logger, resolveTimeout time.Duration) *ScionHostResolver {
	return &ScionHostResolver{
		resolver: NewPANResolver(
			logger.With(zap.String("component", "resolver")),
			resolveTimeout,
		),
		logger: logger,
	}
}

func (s ScionHostResolver) HandleRedirectBackOrError(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return utils.NewHandlerError(http.StatusMethodNotAllowed, errors.New("HTTP GET allowed only"))
	}

	q := r.URL.Query()
	urls, ok := q["url"]
	if !ok || len(urls) != 1 {
		return utils.NewHandlerError(http.StatusBadRequest, errors.New("URL parameter 'url' must contain exaclty one value"))
	}
	l := s.logger.With(zap.String("url", urls[0]))

	l.Debug("Parsing URL.")
	url, err := url.Parse(urls[0])
	if err != nil {
		l.With(zap.Error(err)).Error("Failed to parse URL.")
		return utils.NewHandlerError(http.StatusBadRequest, err)
	}

	l.Debug("Resolving URL.")
	addr, err := s.resolver.Resolve(r.Context(), url.Host)
	if err != nil || addr.IsZero() {
		l.Info("Failed to resolve URL.")
		return utils.NewHandlerError(http.StatusServiceUnavailable, err)
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	l.With(zap.String("redirect", url.String())).Info("Redirecting.")
	http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
	return nil
}

// handleHostResolutionRequest parses requests in the form: /resolve?host=XXX
// If the PAN lib cannot resolve the host, it sends back an empty response.
func (s ScionHostResolver) HandleHostResolutionRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return utils.NewHandlerError(http.StatusMethodNotAllowed, errors.New("HTTP GET allowed only"))
	}

	q := r.URL.Query()
	hosts, ok := q["host"]
	if !ok || len(hosts) > 1 {
		return utils.NewHandlerError(http.StatusBadRequest, errors.New("URL parameter 'host' must contain exaclty one value"))
	}

	addr, err := s.resolver.Resolve(r.Context(), hosts[0])
	if err != nil {
		return utils.NewHandlerError(http.StatusInternalServerError, err)
	} else if addr.IsZero() {
		// send back empty response
		w.WriteHeader(http.StatusOK)
		return nil
	}

	buf := &bytes.Buffer{}
	buf.WriteString(addr.String())
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())

	return nil
}

type Resolver interface {
	Resolve(ctx context.Context, host string) (pan.UDPAddr, error)
}

type panResolver struct {
	logger         *zap.Logger
	resolveTimeout time.Duration
}

func NewPANResolver(logger *zap.Logger, resolveTimeout time.Duration) *panResolver {
	return &panResolver{
		logger:         logger,
		resolveTimeout: resolveTimeout,
	}
}

var ErrResolveTimeout = fmt.Errorf("resolve timeout")

func (r panResolver) Resolve(ctx context.Context, host string) (pan.UDPAddr, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, r.resolveTimeout)
	defer cancel()

	addrc, errc := make(chan pan.UDPAddr, 1), make(chan error)
	go r.resolve(ctxTimeout, host, addrc, errc)

	select {
	case <-ctxTimeout.Done():
		return pan.UDPAddr{}, ErrResolveTimeout
	case err := <-errc:
		return pan.UDPAddr{}, err
	case addr := <-addrc:
		return addr, nil
	}
}

func (r panResolver) resolve(ctx context.Context, host string, addrc chan pan.UDPAddr, errc chan error) {
	log := r.logger.With(zap.String("host", host))

	addr, err := pan.ResolveUDPAddr(ctx, host)
	if err != nil {
		ok := errors.As(err, &pan.HostNotFoundError{})
		if ok {
			log.Debug("SCION disabled.")
			addrc <- pan.UDPAddr{}
			return
		}

		// in general, if there was an error, it was likely "missing port",
		// so try adding a bogus port to take advantage of standard library's
		// robust parser
		// (don't overwrite original error though; might still be relevant)
		var err2 error
		addr, err2 = pan.ResolveUDPAddr(ctx, host+":0")
		if err2 != nil {
			ok := errors.As(err2, &pan.HostNotFoundError{})
			if ok {
				log.Debug("SCION disabled.")
				addrc <- pan.UDPAddr{}
				return
			}
			log.Error("Failed to resolve host.", zap.Error(err))
			errc <- err
			return
		}
	}
	log = log.With(zap.String("addr", addr.String()))
	log.Debug("SCION enabled.")
	addrc <- addr
}
