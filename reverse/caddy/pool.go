// Copyright 2024 Anapaya Systems, ETH Zurich
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

package caddy

import (
	"github.com/caddyserver/caddy/v2"

	"github.com/scionassociation/http-scion/reverse"
)

// UsagePool is a type safe caddy.UsagePool
type UsagePool[K comparable, V any] struct {
	pool *caddy.UsagePool
}

func NewUsagePool[K comparable, V any]() *UsagePool[K, V] {
	return &UsagePool[K, V]{
		pool: caddy.NewUsagePool(),
	}
}

func (p *UsagePool[K, V]) LoadOrNew(key K, construct func() (reverse.Destructor, error)) (V, bool, error) {
	v, l, err := p.pool.LoadOrNew(key, func() (caddy.Destructor, error) {
		d, err := construct()
		if err != nil {
			return nil, err
		}
		return d, nil
	})
	if err != nil {
		var zero V
		return zero, l, err
	}
	return v.(V), l, nil
}

func (p *UsagePool[K, T]) Delete(key K) (bool, error) {
	return p.pool.Delete(key)
}
