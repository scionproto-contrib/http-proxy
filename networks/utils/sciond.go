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
package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/private/app/env"
)

const (
	initTimeout = 1 * time.Second
)

var singletonHostContext hostContext
var initOnce sync.Once

// hostContext contains the information needed to connect to the host's local SCION stack,
// i.e. the connection to sciond.
type hostContext struct {
	env       env.SCION
	sciondMap map[addr.IA]daemon.Connector
}

// host initialises and returns the singleton hostContext.
func Host() *hostContext {
	initOnce.Do(mustInitHostContext)
	return &singletonHostContext
}

func mustInitHostContext() {
	sciondMap := make(map[addr.IA]daemon.Connector)
	env, err := loadEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading SCION environement: %v\n", err)
		os.Exit(1)
	}
	singletonHostContext = hostContext{
		sciondMap: sciondMap,
		env:       env,
	}
}

func (hc *hostContext) SCIONDConn(ia addr.IA) (daemon.Connector, error) {
	conn, ok := hc.sciondMap[ia]
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
		defer cancel()
		var err error
		conn, err = hc.findSciond(ctx, ia)
		if err != nil {
			return nil, err
		}
		hc.sciondMap[ia] = conn
	}
	return conn, nil
}

func (hc *hostContext) findSciond(ctx context.Context, ia addr.IA) (daemon.Connector, error) {
	as, ok := hc.env.ASes[ia]
	if !ok {
		return nil, fmt.Errorf("AS %v not found in environment", ia)
	}
	sciondConn, err := daemon.NewService(as.DaemonAddress).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to AS %s SCIOND at %s: %w", ia, as.DaemonAddress, err)
	}
	return sciondConn, nil
}

func loadEnv() (env.SCION, error) {
	envFile := os.Getenv("SCION_ENV_FILE")
	if envFile == "" {
		envFile = "/etc/scion/environment.json"
	}
	raw, err := os.ReadFile(envFile)
	if err != nil {
		return env.SCION{}, err
	}
	var e env.SCION
	if err := json.Unmarshal(raw, &e); err != nil {
		return env.SCION{}, err
	}
	return e, nil
}
