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

package utils

// HandlerError is an error that can be returned by a handler to specify a status code
// and an error message. It is used as a wrapper around the original error to bubble up
// the status code to the HTTP response.
type HandlerError struct {
	Err        error
	StatusCode int
}

func NewHandlerError(statusCode int, err error) error {
	if he, ok := err.(*HandlerError); ok {
		if he.StatusCode == 0 {
			he.StatusCode = statusCode
		}
		return he
	}
	return &HandlerError{
		Err:        err,
		StatusCode: statusCode,
	}
}

func (h *HandlerError) Error() string {
	if h.Err != nil {
		return h.Err.Error()
	}
	return ""
}
