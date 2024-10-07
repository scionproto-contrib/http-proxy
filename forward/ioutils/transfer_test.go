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

package ioutils

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStream(t *testing.T) {
	rb := new(bytes.Buffer)
	wb := new(bytes.Buffer)

	rb.WriteString("hello, world.")

	err := stream(rb, wb)
	require.NoError(t, err)
	assert.Equal(t, "hello, world.", wb.String(), "stream did not work properly")
}

func TestDualStream(t *testing.T) {
	rbA := new(bytes.Buffer)
	wbA := new(bytes.Buffer)

	rwbB := new(bytes.Buffer)

	rbA.WriteString("hello, Bob.")
	rwbB.WriteString("hello, Alice.")

	err := DualStream(rwbB, rbA, wbA)
	require.NoError(t, err)
	time.Sleep(1 * time.Second) // streaming from A to B is async

	assert.Equal(t, "hello, Alice.", wbA.String(), "Dual stream to A did not work properly")
	assert.Equal(t, "hello, Bob.", rwbB.String(), "Dual stream to B did not work properly")
}
func TestDualStream_EmptyInput(t *testing.T) {
	rbA := new(bytes.Buffer)
	wbA := new(bytes.Buffer)

	rwbB := new(bytes.Buffer)

	err := DualStream(rwbB, rbA, wbA)
	require.NoError(t, err)
	time.Sleep(1 * time.Second) // streaming from A to B is async

	assert.Empty(t, wbA.String(), "Dual stream to A should be empty")
	assert.Empty(t, rwbB.String(), "Dual stream to B should be empty")
}

func TestDualStream_LargerInput(t *testing.T) {
	rbA := new(bytes.Buffer)
	wbA := new(bytes.Buffer)

	rwbB := new(bytes.Buffer)

	largeStringAlice := make([]byte, 32*1024) // 1MB of data
	for i := range largeStringAlice {
		largeStringAlice[i] = 'a'
	}
	largeStringBob := make([]byte, 256*1024) // 1MB of data
	for i := range largeStringBob {
		largeStringBob[i] = 'b'
	}

	rbA.Write(largeStringBob)
	rwbB.Write(largeStringAlice)

	err := DualStream(rwbB, rbA, wbA)
	require.NoError(t, err)
	time.Sleep(5 * time.Second) // streaming from A to B is async, being a bit linient here with the sleep

	fmt.Println("A:", wbA.Len())
	fmt.Println("B:", rwbB.Len())

	assert.Equal(t, string(largeStringAlice), wbA.String(), "Dual stream to A did not work properly with large input")
	assert.Equal(t, string(largeStringBob), rwbB.String(), "Dual stream to B did not work properly with large input")
}

func TestDualStream_WithResponseWriter(t *testing.T) {
	rbA := new(bytes.Buffer)
	wbA := new(bytes.Buffer)

	rwbB := new(bytes.Buffer)

	rbA.WriteString("hello, Bob.")
	rwbB.WriteString("hello, Alice.")

	// Mock http.ResponseWriter
	mockResponseWriter := &mockResponseWriter{Buffer: wbA}

	err := DualStream(rwbB, rbA, mockResponseWriter)
	require.NoError(t, err)
	time.Sleep(1 * time.Second) // streaming from A to B is async

	assert.Equal(t, "hello, Alice.", wbA.String(), "Dual stream to A did not work properly")
	assert.Equal(t, "hello, Bob.", rwbB.String(), "Dual stream to B did not work properly")
}

// mockResponseWriter is a mock implementation of http.ResponseWriter
type mockResponseWriter struct {
	Buffer *bytes.Buffer
}

func (m *mockResponseWriter) Header() http.Header {
	return http.Header{}
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	return m.Buffer.Write(data)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {}

func (m *mockResponseWriter) Flush() {}
