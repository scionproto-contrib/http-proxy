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
package session

import (
	"net/http"
	"os"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type invalidDataType struct{}

type testingStore struct {
	session *sessions.Session
}

func newTestingStore() testingStore {
	s := testingStore{}
	s.session = sessions.NewSession(s, "testing")
	return s
}

func (s testingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s.session.IsNew = false
	return s.session, nil
}

func (s testingStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s.session.IsNew = true
	return s.session, nil
}

func (s testingStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	return nil
}

func TestMain(m *testing.M) {
	sessionStore = newTestingStore()

	code := m.Run()
	os.Exit(code)
}

func TestSessionData(t *testing.T) {
	cases := map[string]struct {
		setData      bool
		expectedData interface{}
		expectedErr  bool
		invalidData  bool
	}{
		"get session data - valid data":      {true, SessionData{"blub", []byte("+")}, false, false},
		"get session data - no data":         {false, SessionData{}, false, false},
		"get session data - wrong data type": {true, invalidDataType{}, true, true},
		"set session data - new session":     {false, SessionData{"blub", []byte("+ 42")}, false, false},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			store := newTestingStore()
			if c.setData {
				store.session.Values[sessionDataKey] = c.expectedData
			}
			sessionStore = store

			if name[:3] == "get" {
				actual, err := GetSessionData(zap.NewNop(), nil)
				if c.expectedErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				if !c.invalidData {
					assert.NotEmpty(t, actual.ID)
					policy := c.expectedData.(SessionData).Policy
					assert.Equal(t, policy, actual.Policy)
				}
			} else {
				data := c.expectedData.(SessionData)
				err := SetSessionData(zap.NewNop(), nil, nil, data)
				if c.expectedErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, data, store.session.Values[sessionDataKey])
			}
		})
	}
}
