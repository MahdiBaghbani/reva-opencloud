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
	"errors"
	"net/url"
	"strings"
)

// NormalizePeerHost canonicalizes the provider segment of an OCM address (the
// part after "@") for peer-host equality. It follows the same https:// trimming
// as GetUserIdFromOCMAddress and also strips an optional http:// prefix. Any
// path after the host is discarded before lowercasing.
func NormalizePeerHost(providerSegment string) (string, error) {
	s := strings.TrimSpace(providerSegment)
	if s == "" {
		return "", errors.New("empty provider segment")
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i != -1 {
		s = s[:i]
	}
	if s == "" {
		return "", errors.New("empty peer host")
	}
	return strings.ToLower(s), nil
}

// PeerHostsEqual reports whether two OCM provider segments denote the same peer
// host after normalization.
func PeerHostsEqual(idpA, idpB string) (bool, error) {
	a, err := NormalizePeerHost(idpA)
	if err != nil {
		return false, err
	}
	b, err := NormalizePeerHost(idpB)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

// AuthorityBase is scheme plus hostname for comparing absolute HTTP(S) protocol
// URIs against an owner-derived discovery authority (current scope uses host
// only; ports are not part of the comparison unit).
type AuthorityBase struct {
	Scheme string
	Host   string
}

// NormalizeAuthorityBase parses rawURI as an absolute http or https URL and
// returns a lowercased scheme and hostname from URL.Hostname().
func NormalizeAuthorityBase(rawURI string) (AuthorityBase, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return AuthorityBase{}, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return AuthorityBase{}, errors.New("authority base requires http or https URL")
	}
	host := u.Hostname()
	if host == "" {
		return AuthorityBase{}, errors.New("authority base requires a host")
	}
	return AuthorityBase{
		Scheme: strings.ToLower(u.Scheme),
		Host:   strings.ToLower(host),
	}, nil
}
