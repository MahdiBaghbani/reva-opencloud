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

// Canonical OCM policy evaluator for Reva.
// See https://github.com/cs3org/OCM-API/blob/develop/IETF-RFC.md for the
// normative spec, in particular the Code Flow and Discovery sections.
package evaluator

import "fmt"

// Config holds the three independent OCM policy knobs that a Reva operator sets.
// Each consuming service (wellknown, ocmd, ocmshareprovider) builds its own
// Config from its TOML section; there is no cross-service singleton.
type Config struct {
	// Whether this server can perform the OAuth authorization-code token
	// exchange defined in the spec's Code Flow section. When true, the
	// server advertises "exchange-token" in capabilities and exposes a
	// tokenEndPoint.
	// Maps to TOML key: enable_token_exchange.
	TokenExchangeEnabled bool

	// Whether ALL incoming shares must carry the "must-exchange-token"
	// WebDAV requirement. When true, the server advertises "token-exchange"
	// in discovery criteria and rejects any share that lacks
	// "must-exchange-token". The spec mandates that advertising
	// "token-exchange" implies "exchange-token" capability, so this
	// requires TokenExchangeEnabled=true.
	// Maps to TOML key: require_token_exchange.
	RequireTokenExchange bool

	// How to send shares toward peers that do not require token exchange.
	// One of:
	//   "prefer-strict" (default): use code flow when the peer advertises
	//       "exchange-token". The spec recommends short-lived tokens over
	//       legacy shared secrets.
	//   "legacy": send with plain bearer, no code flow.
	//   "strict": refuse to share with peers that do not advertise the
	//       "exchange-token" capability.
	// Maps to TOML key: legacy_peer_policy.
	LegacyPeerPolicy string
}

var validLegacyPeerPolicies = map[string]bool{
	"legacy":        true,
	"prefer-strict": true,
	"strict":        true,
}

// Validate rejects contradictory knob combinations that would make the
// server advertise capabilities it cannot actually honour.
func (c *Config) Validate() error {
	if c.LegacyPeerPolicy == "" {
		c.LegacyPeerPolicy = "prefer-strict"
	}
	if !validLegacyPeerPolicies[c.LegacyPeerPolicy] {
		return fmt.Errorf("invalid legacy_peer_policy %q", c.LegacyPeerPolicy)
	}
	if c.RequireTokenExchange && !c.TokenExchangeEnabled {
		return fmt.Errorf("require_token_exchange needs enable_token_exchange to be true")
	}
	if c.LegacyPeerPolicy == "strict" && !c.TokenExchangeEnabled {
		return fmt.Errorf("legacy_peer_policy=strict needs enable_token_exchange to be true")
	}
	return nil
}
