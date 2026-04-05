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

// SelectionOutcome is the runtime branch for discovery and compatibility.
type SelectionOutcome int

const (
	// OutcomeOwnerDerived uses persisted authority_origin for discovery.
	OutcomeOwnerDerived SelectionOutcome = iota
	// OutcomeLegacyURIOrigin uses the WebDAV (or protocol) origin string supplied by the caller.
	OutcomeLegacyURIOrigin
	// OutcomeLegacyMissingRecord means no reva-receive-authority entry; caller uses legacy behavior.
	OutcomeLegacyMissingRecord
	// OutcomeLegacyInvalidRecord means the entry was present but not a valid Plan 01 record.
	OutcomeLegacyInvalidRecord
)

// Selection is the result of applying the record contract to a concrete share row.
type Selection struct {
	Outcome SelectionOutcome
	// DiscoveryRoot is the origin to use for token or discovery calls when non-empty.
	// For OutcomeOwnerDerived it is the record's AuthorityOrigin.
	// For OutcomeLegacyURIOrigin it is davOrigin from the caller.
	// For missing or invalid records it is davOrigin so existing DAV-based discovery can continue.
	DiscoveryRoot string
}

// Select chooses the discovery root given an optional record and the current protocol/DAV origin.
// davOrigin should be the raw origin for the remote endpoint (for example scheme plus host from the WebDAV base URL).
// When the record is missing or invalid, DiscoveryRoot is still set to davOrigin so callers can keep legacy paths.
func Select(record *Record, davOrigin string) Selection {
	if record == nil {
		return Selection{
			Outcome:       OutcomeLegacyMissingRecord,
			DiscoveryRoot: davOrigin,
		}
	}
	if err := record.Validate(); err != nil {
		return Selection{
			Outcome:       OutcomeLegacyInvalidRecord,
			DiscoveryRoot: davOrigin,
		}
	}
	switch record.SelectionMode {
	case SelectionModeOwnerDerived:
		return Selection{
			Outcome:       OutcomeOwnerDerived,
			DiscoveryRoot: record.AuthorityOrigin,
		}
	case SelectionModeLegacyURIOrigin:
		return Selection{
			Outcome:       OutcomeLegacyURIOrigin,
			DiscoveryRoot: davOrigin,
		}
	default:
		return Selection{
			Outcome:       OutcomeLegacyInvalidRecord,
			DiscoveryRoot: davOrigin,
		}
	}
}
