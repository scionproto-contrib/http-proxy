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

package networks

import (
	"fmt"
)

// Destructor defines an interface for objects that can be destructed.
type Destructor interface {
	Destruct() error
}

// Reusable is an interface to an object that can be used multiple times.
// It extends the Destructor interface with a Close method. The Close method
// should be called when the object is no longer needed from the caller.
type Reusable interface {
	Destructor
	Close() error
}

// Pool defines the interface for thread-safe map implementations
// that pools values based on usage (reference counting).
type Pool[K comparable, V any] interface {
	LoadOrNew(key K, construct func() (Destructor, error)) (V, bool, error)
	Delete(key K) (bool, error)
}

func PoolKey(network string, address string) string {
	return fmt.Sprintf("%s:%s", network, address)
}
