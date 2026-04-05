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

package ocmd

import (
	"testing"

	"github.com/cs3org/reva/v3/pkg/utils/cfg"
)

func TestConfigDecodeRequiresProviderDomain(t *testing.T) {
	t.Helper()
	var c config
	err := cfg.Decode(map[string]any{
		"gatewaysvc": "127.0.0.1:9142",
	}, &c)
	if err == nil {
		t.Fatal("expected validation error when provider_domain is missing")
	}
}

func TestConfigDecodeAcceptsProviderDomain(t *testing.T) {
	t.Helper()
	var c config
	err := cfg.Decode(map[string]any{
		"gatewaysvc":      "127.0.0.1:9142",
		"provider_domain": "share.example.org",
	}, &c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.ProviderDomain != "share.example.org" {
		t.Fatalf("ProviderDomain = %q", c.ProviderDomain)
	}
}

func TestConfigDecodeTrimsProviderDomain(t *testing.T) {
	t.Helper()
	var c config
	err := cfg.Decode(map[string]any{
		"gatewaysvc":      "127.0.0.1:9142",
		"provider_domain": "  share.example.org \t",
	}, &c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.ProviderDomain != "share.example.org" {
		t.Fatalf("ProviderDomain after trim = %q", c.ProviderDomain)
	}
}

func TestConfigDecodeRejectsWhitespaceOnlyProviderDomain(t *testing.T) {
	t.Helper()
	var c config
	err := cfg.Decode(map[string]any{
		"gatewaysvc":      "127.0.0.1:9142",
		"provider_domain": "   \t  ",
	}, &c)
	if err == nil {
		t.Fatal("expected validation error for whitespace-only provider_domain")
	}
}
