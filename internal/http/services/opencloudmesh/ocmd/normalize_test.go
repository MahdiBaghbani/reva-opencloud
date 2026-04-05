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
)

func TestNormalizePeerHost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "plain host", in: "remote.example.org", want: "remote.example.org"},
		{name: "uppercase host", in: "Remote.EXAMPLE.org", want: "remote.example.org"},
		{name: "https prefix", in: "https://remote.example.org", want: "remote.example.org"},
		{name: "http prefix", in: "http://remote.example.org", want: "remote.example.org"},
		{name: "host with path", in: "https://remote.example.org/ocm", want: "remote.example.org"},
		{name: "empty", in: "", wantErr: true},
		{name: "only scheme stripped empty", in: "https://", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePeerHost(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("NormalizePeerHost(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPeerHostsEqual(t *testing.T) {
	ok, err := PeerHostsEqual("https://A.example.org", "http://a.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected equal hosts")
	}
	ok, err = PeerHostsEqual("b.example.org", "c.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected different hosts")
	}
	_, err = PeerHostsEqual("", "x")
	if err == nil {
		t.Fatal("expected error for empty idp")
	}
}

func TestNormalizeAuthorityBase(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    AuthorityBase
		wantErr bool
	}{
		{
			name: "https with path",
			raw:  "https://Remote.example.org:8443/files/x",
			want: AuthorityBase{Scheme: "https", Host: "remote.example.org"},
		},
		{
			name: "http host",
			raw:  "http://NC.docker/remote.php/dav/x",
			want: AuthorityBase{Scheme: "http", Host: "nc.docker"},
		},
		{
			name:    "ftp unsupported",
			raw:     "ftp://x/y",
			wantErr: true,
		},
		{
			name:    "relative",
			raw:     "/only/path",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAuthorityBase(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNormalizeAuthorityBaseSchemeDiffers(t *testing.T) {
	a, err := NormalizeAuthorityBase("https://same.host")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeAuthorityBase("http://same.host")
	if err != nil {
		t.Fatal(err)
	}
	if a.Scheme == b.Scheme {
		t.Fatalf("schemes should differ: %#v vs %#v", a, b)
	}
	if a.Host != b.Host {
		t.Fatalf("hosts should match: %#v vs %#v", a, b)
	}
}
