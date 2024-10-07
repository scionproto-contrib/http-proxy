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

package panpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/pkg/addr"
	"go.uber.org/zap"

	"github.com/scionassociation/caddy-scion/forward/session"
)

type DialerManager interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request) error // set policy endpoint
	GetDialer(sessionData session.SessionData, useScion bool) (PANDialer, error)
	Start() error
	Stop() error
}

type ContextDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

type PANDialer interface {
	ContextDialer
	SetPolicy(policy pan.Policy) error
	GetPolicy() pan.Policy
	GetMetrics(filteredAddrs []string) (*DialerMetrics, error)

	HasOpenConnections() (bool, error)
	HasDialedWithinTimeWindow(t time.Duration) (bool, error)
}

type policyManager struct {
	logger      *zap.Logger
	dialTimeout time.Duration

	stdDialer PANDialer

	// XXX(JordiSubira): Shared dialers have their pros and cons. They are shared among all sessions
	// and thus can be reused, but they are also shared among all sessions and thus path information
	// from other sessions can leak if we expose it to the clients. This is a security concern and
	// at the moment we are not exposing path information to the clients. This is why we are using
	// shared dialers. If we decide to expose path information to the clients, we should probably
	// use a custom dialer for each session.
	sharedSDialer PANDialer
	// cache of recently used dialers with at least one open connection, otherwise they are periodically purged
	customSDialers *dialerPool

	purge         bool
	purgeTimeout  time.Duration
	purgeInterval time.Duration
	purgeTicker   *time.Ticker
}

func NewPolicyManager(logger *zap.Logger, dialTimeout time.Duration, purge bool, purgeTimeout, purgeInterval time.Duration) *policyManager {
	return &policyManager{
		logger:         logger,
		dialTimeout:    dialTimeout,
		stdDialer:      NewStdDialer(logger, dialTimeout),
		sharedSDialer:  NewSCIONDialer(logger, dialTimeout, true),
		customSDialers: newDialerPool(),
		purge:          purge,
		purgeTimeout:   purgeTimeout,
		purgeInterval:  purgeInterval,
	}
}

func (h *policyManager) Start() error {
	if !h.purge {
		return nil
	}

	h.logger.Info("Starting inactive dialers purge ticker loop.",
		zap.String("purge-interval", h.purgeInterval.String()),
		zap.String("purge-timeout", h.purgeTimeout.String()))
	h.purgeTicker = time.NewTicker(h.purgeInterval)
	go func() {
		for range h.purgeTicker.C {
			h.logger.Debug("Purging abandoned dialers.")
			h.purgeAbandonedDialers()
		}
	}()

	return nil
}

func (h *policyManager) Stop() error {
	if h.purgeTicker != nil {
		h.logger.Debug("Stopping inactive dialers purge ticker loop.")
		h.purgeTicker.Stop()
	}
	return nil
}

func (h *policyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPut {
		return caddyhttp.Error(http.StatusMethodNotAllowed, errors.New("HTTP PUT allowed only"))
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	log := h.logger.With(zap.String("policy", string(body)))

	policy, err := parsePolicy(body)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	err = h.persistPolicy(w, r, body, policy)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	log.Debug("Policy persisted.")

	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *policyManager) GetDialer(sd session.SessionData, useScion bool) (PANDialer, error) {
	log := h.logger.With(zap.String("session-id", sd.ID), zap.Bool("use-scion", useScion))

	// std dialer
	if !useScion {
		log.Debug("Using standard dialer.")
		return h.stdDialer, nil
	}

	// shared dialer
	if len(sd.Policy) == 0 {
		log.Debug("No path policy configured; using shared scion dialer.")
		return h.sharedSDialer, nil
	}

	// custom dialer
	dialer, loaded := h.loadOrNewDialer(sd.ID)
	if loaded {
		log.Debug("Resuing custom scion dialer.")
	} else {
		log.Debug("Using fresh custom scion dialer.")
	}

	// ensure policy
	policy, err := parsePolicy(sd.Policy)
	if err != nil {
		return nil, err
	}

	h.logger.Debug("Using policy.", zap.String("path-policy", string(sd.Policy)))
	err = dialer.SetPolicy(policy)
	if err != nil {
		return nil, err
	}

	return dialer, nil
}

func (h *policyManager) loadOrNewDialer(id string) (PANDialer, bool) {
	if dialer, ok := h.customSDialers.Load(id); ok {
		return dialer, true
	}

	d := NewSCIONDialer(h.logger, h.dialTimeout, false)
	h.customSDialers.Store(id, d)
	return d, false
}

func (h *policyManager) persistPolicy(w http.ResponseWriter, r *http.Request, rawPolicy []byte, policy pan.Policy) error {
	// save in session
	sessionData, err := session.GetSessionData(h.logger, r)
	if err != nil {
		return err
	}
	h.logger.Debug("Having session.", zap.String("session-id", sessionData.ID))

	sessionData.Policy = rawPolicy

	err = session.SetSessionData(h.logger, w, r, sessionData)
	if err != nil {
		return err
	}

	// save in dialer and update open connections
	d, err := h.GetDialer(sessionData, true)
	if err != nil {
		return err
	}

	h.logger.Debug("Persisting policy.", zap.String("path-policy", string(rawPolicy)))
	err = d.SetPolicy(policy)
	if err != nil {
		return err
	}

	return nil
}

// this works under the assumption the customSDialers only holds dialer not currently in use
func (h *policyManager) purgeAbandonedDialers() {
	cleaner := func(id string, d PANDialer) bool {
		h.logger.Debug("Checking dialer for potential purge.", zap.String("session-id", id))

		// if there are connection, dont purge
		hasOpenConnections, err := d.HasOpenConnections()
		if err != nil {
			h.logger.Warn("Failed to check dialer for open connections.", zap.Error(err))
			return false
		}
		if hasOpenConnections {
			h.logger.Debug("Keeping dialer with open connections.")
			return false
		}

		// Check if the dialer has dialed within the specified time window
		hasDialedRecently, err := d.HasDialedWithinTimeWindow(h.purgeTimeout)
		if err != nil {
			h.logger.Warn("Failed to check dialer for recent dialing.", zap.Error(err))
			return false
		}
		if hasDialedRecently {
			h.logger.Debug("Keeping dialer with recent dialing.")
			return false
		}

		h.logger.Debug("Purging dialer.", zap.String("session-id", id))
		return true
	}
	h.customSDialers.Cleanup(cleaner)
}

// See https://docs.scion.org/en/latest/dev/design/PathPolicy.html.
// example ACL policy: + 1-ff00:0:133, - 1-ff00:0:120, +
// example sequence policy: 1-ff00:0:133#0 1-ff00:0:120#2,1 0 0 1-ff00:0:110#0
//
// XXX(JordiSubira): Note that we expect as input either a ACL or a show path formatted sequence.
// The show path format is a string with the following format:
// <ingress> <ia> <egress> > <ingress> <ia> <egress> > ... <ingress> <ia> <egress>
// this syntax is different from the one used in the sequence policy.
// We may want to expect sequence policies directly in the future.
func parsePolicy(b []byte) (pan.Policy, error) {
	var acl pan.ACL
	err := acl.UnmarshalJSON(b)
	if err == nil {
		return &acl, nil
	}

	var s string
	err2 := json.Unmarshal(b, &s)
	if err2 != nil {
		return nil, fmt.Errorf("not an ACL: %s; not a sequence: %s", err.Error(), err2.Error())
	}
	seqStr, err2 := parseShowPathToSeq(s)
	if err2 != nil {
		return nil, fmt.Errorf("not an ACL: %s; not a sequence: %s", err.Error(), err2.Error())
	}
	sequence, err2 := pan.NewSequence(seqStr)
	if err2 != nil {
		return nil, fmt.Errorf("not an ACL: %s; not a sequence: %s", err.Error(), err2.Error())
	}

	return sequence, nil
}

func parseShowPathToSeq(s string) (string, error) {
	steps, err := parseShowPaths(s)
	if err != nil {
		return "", err
	}
	return steps.ToSequenceStr(), nil
}

func parseShowPaths(s string) (steps, error) {
	iaInterfaces := strings.Split(s, ">")

	if len(iaInterfaces) < 2 {
		return nil, fmt.Errorf("iaInterfaces length %d < 2", len(iaInterfaces))
	}

	steps := make([]step, len(iaInterfaces))
	var err error

	// Add special value to the beginning and end of the path
	iaInterfaces[0] = "0 " + iaInterfaces[0]
	iaInterfaces[len(steps)-1] = iaInterfaces[len(steps)-1] + " 0"

	for i := 0; i < len(steps); i++ {
		steps[i], err = stringToStep(strings.Split(iaInterfaces[i], " "))
		if err != nil {
			return nil, err
		}
	}

	return steps, nil
}

type step struct {
	IA      addr.IA
	Ingress int
	Egress  int
}

func stringToStep(s []string) (step, error) {
	var step step
	var err error
	if len(s) != 3 {
		return step, fmt.Errorf("wrong size %d != 3", len(s))
	}
	step.IA, err = addr.ParseIA(s[1])
	if err != nil {
		return step, err
	}
	step.Ingress, err = strconv.Atoi(s[0])
	if err != nil {
		return step, err
	}
	step.Egress, err = strconv.Atoi(s[2])
	if err != nil {
		return step, err
	}
	return step, nil
}

type steps []step

func (s steps) ToSequenceStr() string {
	// 19-ffaa:1:f5c 1>370 19-ffaa:0:1303 1>5 19-ffaa:0:1301 3>5 18-ffaa:0:1201 8>1 18-ffaa:0:1206 128>1 18-ffaa:1:feb
	// 19-ffaa:1:f5c#1 19-ffaa:0:1303#370,1 19-ffaa:0:1301#5,3 18-ffaa:0:1201#5,8 18-ffaa:0:1206#1,128 18-ffaa:1:feb#1
	b := &strings.Builder{}
	for i, step := range s {
		if i == 0 {
			fmt.Fprintf(b, "%s #%d", step.IA.String(), step.Egress)
			continue
		}
		if i == len(s)-1 {
			fmt.Fprintf(b, " %s #%d", step.IA.String(), step.Ingress)
			continue
		}
		fmt.Fprintf(b, " %s #%d,%d", step.IA.String(), step.Ingress, step.Egress)
	}
	return b.String()
}

// dialerPool functions as a dialer cache for scion dialers with a custom policy
// despite the operations of this dialerpool are protected by a mutex
// on a higher level, it is not thread-safe:
// process A may load a dialer form the map
// process B is electing the same dialer for purging and is deleted from the cache
// process A may still use the same dialer
// (load-delete-dial interleaving)
// for this application this is fine as the penalty is a simple overhead of creating
// a new dialer in the next request that want to use a custom dialer
type dialerPool struct {
	store   map[string]PANDialer
	storeMu sync.Mutex
}

func newDialerPool() *dialerPool {
	return &dialerPool{
		store:   make(map[string]PANDialer),
		storeMu: sync.Mutex{},
	}
}

func (p *dialerPool) Store(id string, d PANDialer) {
	p.storeMu.Lock()
	defer p.storeMu.Unlock()
	p.store[id] = d
}

func (p *dialerPool) Load(id string) (PANDialer, bool) {
	p.storeMu.Lock()
	defer p.storeMu.Unlock()
	if d, ok := p.store[id]; ok {
		return d, true
	}
	return nil, false
}

// if the clean function returns true for a given id/dialer pair, it is deleted from the map
func (p *dialerPool) Cleanup(clean func(id string, d PANDialer) bool) {
	for id, d := range p.store {
		if clean(id, d) {
			p.storeMu.Lock()
			delete(p.store, id)
			defer p.storeMu.Unlock()
		}
	}
}
