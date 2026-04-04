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

package evaluator

import "testing"

func TestValidConfigPasses(t *testing.T) {
	e, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: true,
		RequireTokenExchange: false,
		LegacyPeerPolicy:    "legacy",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ev := e.Evaluation()
	if !ev.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable=true")
	}
	if ev.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange=false")
	}
	if ev.LegacyPeerPolicy != "legacy" {
		t.Errorf("got policy %q, want legacy", ev.LegacyPeerPolicy)
	}
}

func TestRequireExchangeWithCapability(t *testing.T) {
	e, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: true,
		RequireTokenExchange: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Evaluation().RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange=true")
	}
}

func TestRequireExchangeWithoutCapabilityFails(t *testing.T) {
	_, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: false,
		RequireTokenExchange: true,
	})
	if err == nil {
		t.Fatal("expected error: cannot require exchange without the capability")
	}
}

func TestStrictPolicyWithoutCapabilityFails(t *testing.T) {
	_, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: false,
		LegacyPeerPolicy:    "strict",
	})
	if err == nil {
		t.Fatal("expected error: strict policy needs exchange capability")
	}
}

func TestInvalidPolicyFails(t *testing.T) {
	_, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: true,
		LegacyPeerPolicy:    "bogus",
	})
	if err == nil {
		t.Fatal("expected error for unrecognised policy value")
	}
}

func TestEmptyPolicyDefaultsToPreferStrict(t *testing.T) {
	e, err := NewLocalEvaluator(Config{
		TokenExchangeEnabled: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Evaluation().LegacyPeerPolicy != "prefer-strict" {
		t.Errorf("got policy %q, want prefer-strict", e.Evaluation().LegacyPeerPolicy)
	}
}
