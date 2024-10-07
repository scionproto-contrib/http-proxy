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

package session

import (
	"encoding/base32"
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.uber.org/zap"
)

// TODO (minor) should seperate ID from data
type SessionData struct {
	ID     string
	Policy []byte // raw policy
}

var sessionStoreMu sync.Mutex
var sessionStore sessions.Store

const (
	sessionKeyLength  = 32
	sessionKeyEnvName = "SESSION_KEY"

	SessionName     = "caddy-scion-forward-proxy"
	sessionDataKey  = "session-data"
	sessionIDLength = 32
)

func init() {
	gob.Register(SessionData{})

	sessionKey := []byte(os.Getenv(sessionKeyEnvName))
	if len(sessionKey) == 0 {
		sessionKey = securecookie.GenerateRandomKey(sessionKeyLength)
	} else if len(sessionKey) != sessionKeyLength {
		panic(fmt.Sprintf("expected session key of %d bits, but was %d", sessionKeyLength, len(sessionKey)))
	}
	sessionStore = sessions.NewCookieStore(sessionKey)
	sessionStoreMu = sync.Mutex{}
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TODO maybe this should be an interface method as well?
func GetSessionData(logger *zap.Logger, r *http.Request) (SessionData, error) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	session, err := sessionStore.Get(r, SessionName)
	if err != nil {
		if multierr, ok := err.(securecookie.MultiError); !ok || !multierr.IsDecode() {
			logger.Warn("Failed to get session from request.", zap.Error(err))
			return SessionData{}, err
		}
		logger.Warn("Failed to decode session from request. Generating a new one...")
	}

	data, ok := session.Values[sessionDataKey]
	if !ok {
		id := base32RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(sessionIDLength))
		logger.Debug("Generating a new session.", zap.String("session-id", id))
		return SessionData{ID: id}, nil
	}

	sd, ok := data.(SessionData)
	if !ok {
		logger.Error("Failed to decode session data.")
		return SessionData{}, fmt.Errorf("invalid session data type: expected sessionData, got %T", data)
	}

	return sd, nil
}

func SetSessionData(logger *zap.Logger, w http.ResponseWriter, r *http.Request, data SessionData) error {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	if len(data.ID) == 0 {
		return fmt.Errorf("invalid session data: no id set")
	}

	session, err := sessionStore.Get(r, SessionName)
	if err != nil {
		if multierr, ok := err.(securecookie.MultiError); !ok || !multierr.IsDecode() {
			logger.Warn("Failed to get session from request.", zap.Error(err))
			return err
		}
		logger.Warn("Failed to decode session from request.")
	}

	session.Values[sessionDataKey] = data

	session.Options = &sessions.Options{
		HttpOnly: true,
	}

	err = session.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}
