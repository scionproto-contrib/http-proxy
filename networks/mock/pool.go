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

package mock

import (
	"errors"
	"sync"

	"github.com/scionproto-contrib/http-proxy/networks"
)

type Pool[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]V
}

func NewPool[K comparable, V any]() *Pool[K, V] {
	return &Pool[K, V]{
		entries: make(map[K]V),
	}
}

func (mp *Pool[K, V]) LoadOrNew(key K, construct func() (networks.Destructor, error)) (V, bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if entry, exists := mp.entries[key]; exists {
		return entry, true, nil
	}

	newEntry, err := construct()
	if err != nil {
		var zero V
		return zero, false, err
	}

	var entry V
	if v, ok := newEntry.(V); ok {
		entry = v
	} else {
		return entry, false, errors.New("type assertion failed")
	}
	mp.entries[key] = entry

	return entry, false, nil
}

func (mp *Pool[K, V]) Delete(key K) (bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if _, exists := mp.entries[key]; !exists {
		return false, nil
	}

	delete(mp.entries, key)
	return true, nil
}

type Reusable struct{}

func (m *Reusable) Destruct() error {
	return nil
}

func (m *Reusable) Close() error {
	return nil
}
