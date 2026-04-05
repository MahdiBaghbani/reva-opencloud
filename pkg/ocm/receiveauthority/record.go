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

// Package receiveauthority holds the versioned reva-receive-authority JSON record
// and runtime selection over discovery roots. Ingress normalization and
// peer-host checks live outside this package.
package receiveauthority

import (
	"fmt"
	"strings"
)

// OpaqueKey is the ReceivedShare.Opaque map key for this record.
const OpaqueKey = "reva-receive-authority"

// OpaqueDecoder is the CS3 OpaqueEntry decoder for JSON payloads.
const OpaqueDecoder = "json"

// Plan 01 contract identifier.
const ContractOwnerAuthorityV1 = "owner-authority-v1"

// Supported record version for Plan 01.
const CurrentVersion = 1

// SelectionMode controls which discovery root applies for compliant rows.
type SelectionMode string

const (
	SelectionModeOwnerDerived    SelectionMode = "owner-derived"
	SelectionModeLegacyURIOrigin SelectionMode = "legacy-uri-origin"
)

// Cohort classifies how the row relates to the new contract (for persistence and later observability).
type Cohort string

const (
	CohortNewCompliant        Cohort = "new-compliant"
	CohortLegacyNormalized    Cohort = "legacy-normalized"
	CohortLegacyGrandfathered Cohort = "legacy-grandfathered"
)

// URIEvidence describes how the protocol URI was judged at ingress.
type URIEvidence string

const (
	URIEvidenceRelative        URIEvidence = "relative"
	URIEvidenceAbsoluteMatch   URIEvidence = "absolute-match"
	URIEvidenceAbsoluteDiverge URIEvidence = "absolute-diverge"
)

// Record is the JSON shape stored under OpaqueKey.
type Record struct {
	Version         int           `json:"version"`
	Contract        string        `json:"contract"`
	AuthorityHost   string        `json:"authority_host"`
	AuthorityOrigin string        `json:"authority_origin"`
	SelectionMode   SelectionMode `json:"selection_mode"`
	Cohort          Cohort        `json:"cohort"`
	URIEvidence     URIEvidence   `json:"uri_evidence"`
}

// Validate checks required fields and allowed enum values for Plan 01.
func (r *Record) Validate() error {
	if r == nil {
		return fmt.Errorf("receiveauthority: nil record")
	}
	if r.Version != CurrentVersion {
		return fmt.Errorf("receiveauthority: unsupported version %d", r.Version)
	}
	if r.Contract != ContractOwnerAuthorityV1 {
		return fmt.Errorf("receiveauthority: unsupported contract %q", r.Contract)
	}
	if strings.TrimSpace(r.AuthorityHost) == "" {
		return fmt.Errorf("receiveauthority: empty authority_host")
	}
	if strings.TrimSpace(r.AuthorityOrigin) == "" {
		return fmt.Errorf("receiveauthority: empty authority_origin")
	}
	switch r.SelectionMode {
	case SelectionModeOwnerDerived, SelectionModeLegacyURIOrigin:
	default:
		return fmt.Errorf("receiveauthority: invalid selection_mode %q", r.SelectionMode)
	}
	switch r.Cohort {
	case CohortNewCompliant, CohortLegacyNormalized, CohortLegacyGrandfathered:
	default:
		return fmt.Errorf("receiveauthority: invalid cohort %q", r.Cohort)
	}
	switch r.URIEvidence {
	case URIEvidenceRelative, URIEvidenceAbsoluteMatch, URIEvidenceAbsoluteDiverge:
	default:
		return fmt.Errorf("receiveauthority: invalid uri_evidence %q", r.URIEvidence)
	}
	return nil
}
