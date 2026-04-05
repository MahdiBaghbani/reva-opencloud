// Copyright 2018-2026 CERN
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// In applying this license, CERN does not waive the privileges and immunities
// granted to it by virtue of its status as an Intergovernmental Organization
// or submit itself to any jurisdiction.

package receiveauthority

import (
	"encoding/json"
	"fmt"

	typespb "github.com/cs3org/go-cs3apis/cs3/types/v1beta1"
)

// EncodeOpaqueEntry returns a CS3 OpaqueEntry carrying the JSON record.
func EncodeOpaqueEntry(r *Record) (*typespb.OpaqueEntry, error) {
	if r == nil {
		return nil, fmt.Errorf("receiveauthority: nil record")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("receiveauthority: marshal: %w", err)
	}
	return &typespb.OpaqueEntry{
		Decoder: OpaqueDecoder,
		Value:   raw,
	}, nil
}

// DecodeOpaqueEntry parses a single OpaqueEntry into a Record and runs Validate.
// On success the record satisfies Plan 01 constraints.
func DecodeOpaqueEntry(e *typespb.OpaqueEntry) (*Record, error) {
	if e == nil {
		return nil, fmt.Errorf("receiveauthority: nil opaque entry")
	}
	if e.Decoder != "" && e.Decoder != OpaqueDecoder {
		return nil, fmt.Errorf("receiveauthority: unexpected decoder %q", e.Decoder)
	}
	if len(e.Value) == 0 {
		return nil, fmt.Errorf("receiveauthority: empty opaque value")
	}
	var r Record
	if err := json.Unmarshal(e.Value, &r); err != nil {
		return nil, fmt.Errorf("receiveauthority: unmarshal: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("receiveauthority: validate after decode: %w", err)
	}
	return &r, nil
}

// DecodeFromOpaqueMap returns the record from m[OpaqueKey], or (nil, nil) if the key is absent.
// If the key is present with a nil entry, or the entry is invalid JSON or fails Validate, it returns an error.
func DecodeFromOpaqueMap(m map[string]*typespb.OpaqueEntry) (*Record, error) {
	if m == nil {
		return nil, nil
	}
	e, ok := m[OpaqueKey]
	if !ok {
		return nil, nil
	}
	if e == nil {
		return nil, fmt.Errorf("receiveauthority: opaque map value for key %q is nil", OpaqueKey)
	}
	return DecodeOpaqueEntry(e)
}
