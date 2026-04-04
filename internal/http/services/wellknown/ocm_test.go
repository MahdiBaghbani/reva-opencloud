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

package wellknown

import (
	"encoding/json"
	"strings"
	"testing"
)

func initHandler(t *testing.T, c *OcmProviderConfig) *wkocmHandler {
	t.Helper()
	h := &wkocmHandler{}
	if err := h.init(c); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	return h
}

func TestInitWithCodeFlowEnabled(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:       "https://cernbox.cern.ch",
		OCMPrefix:      "ocm",
		EnableTokenExchange: true,
	})

	if h.data.TokenEndPoint == "" {
		t.Error("expected tokenEndPoint to be set when code-flow is enabled")
	}
	if h.data.TokenEndPoint != "https://cernbox.cern.ch/ocm/token" {
		t.Errorf("tokenEndPoint: got %s, want https://cernbox.cern.ch/ocm/token", h.data.TokenEndPoint)
	}

	found := false
	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected exchange-token capability, got %v", h.data.Capabilities)
	}
}

func TestInitWithCodeFlowDisabled(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:       "https://cernbox.cern.ch",
		OCMPrefix:      "ocm",
		EnableTokenExchange: false,
	})

	if h.data.TokenEndPoint != "" {
		t.Errorf("expected empty tokenEndPoint when code-flow is disabled, got %s", h.data.TokenEndPoint)
	}

	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			t.Error("exchange-token capability should not be present when code-flow is disabled")
		}
	}
}

func TestInitWithNoEndpoint(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		EnableTokenExchange: true,
	})

	if h.data.Enabled {
		t.Error("expected discovery to be disabled when no endpoint is configured")
	}
	if h.data.TokenEndPoint != "" {
		t.Errorf("expected empty tokenEndPoint when disabled, got %s", h.data.TokenEndPoint)
	}
}

func TestInitCapabilitiesDoNotDuplicateExchangeToken(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:       "https://cernbox.cern.ch",
		EnableTokenExchange: true,
	})

	count := 0
	for _, cap := range h.data.Capabilities {
		if strings.Contains(cap, "exchange-token") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 exchange-token capability, got %d in %v", count, h.data.Capabilities)
	}
}

func TestCriteriaEmptyByDefault(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:       "https://cernbox.cern.ch",
		EnableTokenExchange: true,
	})
	if h.data.Criteria == nil {
		t.Fatal("criteria must not be nil")
	}
	if len(h.data.Criteria) != 0 {
		t.Errorf("expected empty criteria, got %v", h.data.Criteria)
	}
}

func TestCriteriaTokenExchangeWhenStrict(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:           "https://cernbox.cern.ch",
		EnableTokenExchange:     true,
		RequireTokenExchange: true,
	})
	found := false
	for _, c := range h.data.Criteria {
		if c == "token-exchange" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected token-exchange in criteria, got %v", h.data.Criteria)
	}
}

func TestCriteriaSerializesAsEmptyArray(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:       "https://cernbox.cern.ch",
		EnableTokenExchange: false,
	})
	b, err := json.Marshal(h.data)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if !strings.Contains(string(b), `"criteria":[]`) {
		t.Errorf("expected criteria:[] in JSON, got %s", string(b))
	}
}

func TestCriteriaRoundTrip(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{
		Endpoint:           "https://cernbox.cern.ch",
		EnableTokenExchange:     true,
		RequireTokenExchange: true,
	})
	b, err := json.Marshal(h.data)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var out OcmDiscoveryData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(out.Criteria) != 1 || out.Criteria[0] != "token-exchange" {
		t.Errorf("round-trip criteria mismatch: got %v", out.Criteria)
	}
}

func TestInitRejectsStrictnessWithoutCodeFlow(t *testing.T) {
	h := &wkocmHandler{}
	err := h.init(&OcmProviderConfig{
		Endpoint:           "https://cernbox.cern.ch",
		EnableTokenExchange:     false,
		RequireTokenExchange: true,
	})
	if err == nil {
		t.Fatal("expected error for strictness without code-flow")
	}
}

func TestDisabledEndpointStillHasEmptyCriteria(t *testing.T) {
	h := initHandler(t, &OcmProviderConfig{})
	if h.data.Criteria == nil || len(h.data.Criteria) != 0 {
		t.Errorf("expected empty criteria for disabled endpoint, got %v", h.data.Criteria)
	}
}
