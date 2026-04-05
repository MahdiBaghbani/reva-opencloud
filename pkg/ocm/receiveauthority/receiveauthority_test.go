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
	"strings"
	"testing"

	typespb "github.com/cs3org/go-cs3apis/cs3/types/v1beta1"
)

func validRecord() *Record {
	return &Record{
		Version:         CurrentVersion,
		Contract:        ContractOwnerAuthorityV1,
		AuthorityHost:   "remote.example.org",
		AuthorityOrigin: "https://remote.example.org",
		SelectionMode:   SelectionModeOwnerDerived,
		Cohort:          CohortNewCompliant,
		URIEvidence:     URIEvidenceRelative,
	}
}

func TestRecordValidate(t *testing.T) {
	t.Parallel()
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("validRecord: %v", err)
	}
	if err := (*Record)(nil).Validate(); err == nil {
		t.Fatal("nil record should fail")
	}
	bad := validRecord()
	bad.Version = 0
	if err := bad.Validate(); err == nil {
		t.Fatal("version 0 should fail")
	}
	bad = validRecord()
	bad.Contract = "other"
	if err := bad.Validate(); err == nil {
		t.Fatal("wrong contract should fail")
	}
	bad = validRecord()
	bad.AuthorityHost = " "
	if err := bad.Validate(); err == nil {
		t.Fatal("blank authority_host should fail")
	}
	bad = validRecord()
	bad.SelectionMode = "nope"
	if err := bad.Validate(); err == nil {
		t.Fatal("bad selection_mode should fail")
	}
	bad = validRecord()
	bad.AuthorityOrigin = " "
	if err := bad.Validate(); err == nil {
		t.Fatal("blank authority_origin should fail")
	}
	bad = validRecord()
	bad.Cohort = "not-a-cohort"
	if err := bad.Validate(); err == nil {
		t.Fatal("bad cohort should fail")
	}
	bad = validRecord()
	bad.URIEvidence = "not-evidence"
	if err := bad.Validate(); err == nil {
		t.Fatal("bad uri_evidence should fail")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	want := validRecord()
	want.SelectionMode = SelectionModeLegacyURIOrigin
	want.Cohort = CohortLegacyGrandfathered
	want.URIEvidence = URIEvidenceAbsoluteMatch

	entry, err := EncodeOpaqueEntry(want)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Decoder != OpaqueDecoder {
		t.Fatalf("decoder: got %q", entry.Decoder)
	}
	got, err := DecodeOpaqueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.Contract != want.Contract ||
		got.AuthorityHost != want.AuthorityHost || got.AuthorityOrigin != want.AuthorityOrigin ||
		got.SelectionMode != want.SelectionMode || got.Cohort != want.Cohort ||
		got.URIEvidence != want.URIEvidence {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, want)
	}
}

func TestDecodeFromOpaqueMap(t *testing.T) {
	t.Parallel()
	r := validRecord()
	entry, err := EncodeOpaqueEntry(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFromOpaqueMap(map[string]*typespb.OpaqueEntry{
		OpaqueKey: entry,
		"other":   {Decoder: "json", Value: []byte(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AuthorityHost != r.AuthorityHost {
		t.Fatalf("got %+v", got)
	}
	got, err = DecodeFromOpaqueMap(nil)
	if err != nil || got != nil {
		t.Fatalf("nil map: got %v err %v", got, err)
	}
	got, err = DecodeFromOpaqueMap(map[string]*typespb.OpaqueEntry{})
	if err != nil || got != nil {
		t.Fatalf("empty map: got %v err %v", got, err)
	}

	_, err = DecodeFromOpaqueMap(map[string]*typespb.OpaqueEntry{
		OpaqueKey: {Decoder: OpaqueDecoder, Value: []byte(`{`)},
	})
	if err == nil {
		t.Fatal("malformed JSON under OpaqueKey should error")
	}
	_, err = DecodeFromOpaqueMap(map[string]*typespb.OpaqueEntry{
		OpaqueKey: {Decoder: OpaqueDecoder, Value: []byte(`{}`)},
	})
	if err == nil {
		t.Fatal("empty semantic JSON under OpaqueKey should fail validate")
	}
}

func TestEncodeInvalidRecord(t *testing.T) {
	t.Parallel()
	_, err := EncodeOpaqueEntry(&Record{Version: 2})
	if err == nil {
		t.Fatal("encode invalid record should fail")
	}
}

func TestDecodeOpaqueEntryErrors(t *testing.T) {
	t.Parallel()
	if _, err := DecodeOpaqueEntry(nil); err == nil {
		t.Fatal("nil entry")
	}
	if _, err := DecodeOpaqueEntry(&typespb.OpaqueEntry{Decoder: "plain", Value: []byte("x")}); err == nil {
		t.Fatal("wrong decoder")
	}
	if _, err := DecodeOpaqueEntry(&typespb.OpaqueEntry{Decoder: OpaqueDecoder}); err == nil {
		t.Fatal("empty value")
	}
	if _, err := DecodeOpaqueEntry(&typespb.OpaqueEntry{Decoder: OpaqueDecoder, Value: []byte(`{`)}); err == nil {
		t.Fatal("bad json")
	}
	// Valid JSON but fails semantic validation (wrong cohort).
	wrongCohort, err := json.Marshal(&Record{
		Version:         CurrentVersion,
		Contract:        ContractOwnerAuthorityV1,
		AuthorityHost:   "h",
		AuthorityOrigin: "https://h",
		SelectionMode:   SelectionModeOwnerDerived,
		Cohort:          "invalid-cohort",
		URIEvidence:     URIEvidenceRelative,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, decErr := DecodeOpaqueEntry(&typespb.OpaqueEntry{Decoder: OpaqueDecoder, Value: wrongCohort})
	if decErr == nil {
		t.Fatal("valid json invalid record should fail")
	}
	if !strings.Contains(decErr.Error(), "cohort") {
		t.Fatalf("expected cohort error, got %v", decErr)
	}
}

func TestSelect(t *testing.T) {
	t.Parallel()
	dav := "https://dav.remote.example.org"

	sel := Select(nil, dav)
	if sel.Outcome != OutcomeLegacyMissingRecord || sel.DiscoveryRoot != dav {
		t.Fatalf("missing: %+v", sel)
	}

	sel = Select(&Record{Version: 1}, dav)
	if sel.Outcome != OutcomeLegacyInvalidRecord || sel.DiscoveryRoot != dav {
		t.Fatalf("invalid: %+v", sel)
	}

	r := validRecord()
	r.SelectionMode = SelectionModeOwnerDerived
	r.AuthorityOrigin = "https://owner.example"
	sel = Select(r, dav)
	if sel.Outcome != OutcomeOwnerDerived || sel.DiscoveryRoot != "https://owner.example" {
		t.Fatalf("owner-derived: %+v", sel)
	}

	r = validRecord()
	r.SelectionMode = SelectionModeLegacyURIOrigin
	sel = Select(r, dav)
	if sel.Outcome != OutcomeLegacyURIOrigin || sel.DiscoveryRoot != dav {
		t.Fatalf("legacy-uri-origin: %+v", sel)
	}
}
