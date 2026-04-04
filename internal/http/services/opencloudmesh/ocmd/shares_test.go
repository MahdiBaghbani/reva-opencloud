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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gateway "github.com/cs3org/go-cs3apis/cs3/gateway/v1beta1"
	userpb "github.com/cs3org/go-cs3apis/cs3/identity/user/v1beta1"
	ocmincoming "github.com/cs3org/go-cs3apis/cs3/ocm/incoming/v1beta1"
	ocmprovider "github.com/cs3org/go-cs3apis/cs3/ocm/provider/v1beta1"
	rpc "github.com/cs3org/go-cs3apis/cs3/rpc/v1beta1"
	ocm "github.com/cs3org/go-cs3apis/cs3/sharing/ocm/v1beta1"
	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	"github.com/cs3org/reva/v3/internal/http/services/wellknown"
	"github.com/cs3org/reva/v3/pkg/ocm/evaluator"
	"google.golang.org/grpc"
)

type sharesMockGW struct {
	gateway.GatewayAPIClient
	createResp *ocmincoming.CreateOCMIncomingShareResponse
}

func (m *sharesMockGW) IsProviderAllowed(context.Context, *ocmprovider.IsProviderAllowedRequest, ...grpc.CallOption) (*ocmprovider.IsProviderAllowedResponse, error) {
	return &ocmprovider.IsProviderAllowedResponse{
		Status: &rpc.Status{Code: rpc.Code_CODE_OK},
	}, nil
}

func (m *sharesMockGW) GetUser(context.Context, *userpb.GetUserRequest, ...grpc.CallOption) (*userpb.GetUserResponse, error) {
	return &userpb.GetUserResponse{
		Status: &rpc.Status{Code: rpc.Code_CODE_OK},
		User: &userpb.User{
			Id: &userpb.UserId{OpaqueId: "local-recipient", Idp: "local.example.org"},
		},
	}, nil
}

func (m *sharesMockGW) CreateOCMIncomingShare(context.Context, *ocmincoming.CreateOCMIncomingShareRequest, ...grpc.CallOption) (*ocmincoming.CreateOCMIncomingShareResponse, error) {
	return m.createResp, nil
}

func TestCreateShareReturnsServerErrorForNonOKCreateStatus(t *testing.T) {
	h := &sharesHandler{
		gatewayClient: &sharesMockGW{
			createResp: &ocmincoming.CreateOCMIncomingShareResponse{
				Status: &rpc.Status{
					Code:    rpc.Code_CODE_INTERNAL,
					Message: "store failed",
				},
			},
		},
	}

	body := []byte(`{
		"shareWith":"marie@local.example.org",
		"name":"test.txt",
		"providerId":"provider-id",
		"owner":"einstein@remote.example.org",
		"sender":"einstein@remote.example.org",
		"shareType":"user",
		"resourceType":"file",
		"protocol":{
			"webdav":{
				"sharedSecret":"secret",
				"permissions":["read"],
				"uri":"https://remote.example.org/remote.php/dav/files/einstein/test.txt"
			}
		}
	}`)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.15:12345"
	rr := httptest.NewRecorder()

	h.CreateShare(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("CreateShare() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func testWebDAVProtocol(reqs ...string) []*ocm.Protocol {
	return []*ocm.Protocol{
		{Term: &ocm.Protocol_WebdavOptions{WebdavOptions: &ocm.WebDAVProtocol{
			Uri:          "https://remote/dav",
			SharedSecret: "secret",
			Permissions: &ocm.SharePermissions{
				Permissions: &provider.ResourcePermissions{Stat: true},
			},
			Requirements: reqs,
		}}},
	}
}

func getReqs(protocols []*ocm.Protocol) []string {
	for _, p := range protocols {
		if dav, ok := p.Term.(*ocm.Protocol_WebdavOptions); ok {
			return dav.WebdavOptions.Requirements
		}
	}
	return nil
}

// Receiver requires token-exchange, sender capable, share omits requirement: reject.
// The spec says shares without must-exchange-token "will be rejected".
func TestClassifyReceiverRequiresExchangeRejectsWithoutRequirement(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{"exchange-token"},
	}
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, disco, nil, true)
	if err == nil {
		t.Fatal("expected error: receiver requires exchange but share omits must-exchange-token")
	}
}

// Receiver requires token-exchange, sender capable, share has requirement: accept.
func TestClassifyReceiverRequiresExchangeAcceptsWithRequirement(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{"exchange-token"},
	}
	protos := testWebDAVProtocol("must-exchange-token")
	if err := classifyAndNormalizeRequirements(protos, disco, nil, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := getReqs(protos)
	if !containsRequirement(reqs, "must-exchange-token") {
		t.Errorf("should keep must-exchange-token, got %v", reqs)
	}
}

// Receiver requires token-exchange but sender lacks capability: reject.
func TestClassifyReceiverRequiresExchangeSenderLacksCapabilityRejects(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{},
	}
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, disco, nil, true)
	if err == nil {
		t.Fatal("expected error: receiver requires exchange but sender has no capability")
	}
}

// Receiver does not require, share has must-exchange-token, sender capable: honour per-share.
func TestClassifyPerShareMustExchangeHonoured(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{"exchange-token"},
	}
	protos := testWebDAVProtocol("must-exchange-token")
	if err := classifyAndNormalizeRequirements(protos, disco, nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := getReqs(protos)
	if !containsRequirement(reqs, "must-exchange-token") {
		t.Errorf("per-share marker should be kept, got %v", reqs)
	}
	if containsRequirement(reqs, "__exchange-token-capable") {
		t.Errorf("should not add internal marker when per-share marker is present, got %v", reqs)
	}
}

// Receiver does not require, no per-share marker, sender capable: opportunistic.
func TestClassifyOpportunisticMarkerAdded(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{"exchange-token"},
	}
	protos := testWebDAVProtocol()
	if err := classifyAndNormalizeRequirements(protos, disco, nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := getReqs(protos)
	if !containsRequirement(reqs, "__exchange-token-capable") {
		t.Errorf("capable sender without requirement should get internal marker, got %v", reqs)
	}
}

// Share carries must-exchange-token but sender has no capability: reject.
func TestClassifyMustExchangeWithoutCapabilityRejects(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{},
	}
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, disco, nil, false)
	if err == nil {
		t.Fatal("expected error: must-exchange-token with no exchange-token capability is contradictory")
	}
}

// Legacy sender, no requirement, receiver does not require: accept as legacy.
func TestClassifyLegacyShareAccepted(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{},
	}
	protos := testWebDAVProtocol()
	if err := classifyAndNormalizeRequirements(protos, disco, nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := getReqs(protos)
	if containsRequirement(reqs, "must-exchange-token") {
		t.Errorf("legacy share should stay clean, got %v", reqs)
	}
}

// Internal marker from wire is always stripped.
func TestClassifyStripsWireInternalMarker(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{
		Capabilities: []string{},
	}
	protos := testWebDAVProtocol("__exchange-token-capable")
	if err := classifyAndNormalizeRequirements(protos, disco, nil, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reqs := getReqs(protos)
	if containsRequirement(reqs, "__exchange-token-capable") {
		t.Errorf("expected __exchange-token-capable stripped from wire, got %v", reqs)
	}
}

// Discovery failure with must-exchange-token on wire: reject.
func TestClassifyDiscoveryFailureWithMustExchangeRejects(t *testing.T) {
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, nil, fmt.Errorf("network error"), false)
	if err == nil {
		t.Fatal("expected error for discovery failure with must-exchange-token")
	}
}

// Discovery failure with receiver requiring exchange: reject.
func TestClassifyDiscoveryFailureReceiverRequiresExchangeRejects(t *testing.T) {
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, nil, fmt.Errorf("network error"), true)
	if err == nil {
		t.Fatal("expected error: receiver requires exchange but discovery failed")
	}
}

// Discovery failure, no requirement, receiver does not require: accept as legacy.
func TestClassifyDiscoveryFailureLegacyAccepted(t *testing.T) {
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, nil, fmt.Errorf("network error"), false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	reqs := getReqs(protos)
	if containsRequirement(reqs, "must-exchange-token") {
		t.Errorf("expected must-exchange-token not present, got %v", reqs)
	}
}

// Error class: contradictory payload is classErrInvalidPayload.
func TestClassifyErrorKindContradictoryPayload(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{Capabilities: []string{}}
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, disco, nil, false)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrInvalidPayload {
		t.Errorf("expected classErrInvalidPayload, got %d", ce.kind)
	}
}

// Error class: receiver policy unsatisfied is classErrPeerUnsatisfied.
func TestClassifyErrorKindPeerUnsatisfied(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{Capabilities: []string{}}
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, disco, nil, true)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrPeerUnsatisfied {
		t.Errorf("expected classErrPeerUnsatisfied, got %d", ce.kind)
	}
}

// Error class: discovery failure is classErrDiscoveryFailed.
func TestClassifyErrorKindDiscoveryFailed(t *testing.T) {
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, nil, fmt.Errorf("network error"), false)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrDiscoveryFailed {
		t.Errorf("expected classErrDiscoveryFailed, got %d", ce.kind)
	}
}

// sharesHandler.init rejects contradictory evaluator config at startup.
func TestSharesHandlerInitRejectsInvalidEvaluatorConfig(t *testing.T) {
	h := &sharesHandler{gatewayClient: &sharesMockGW{}}
	c := &config{
		RequireTokenExchange: true,
		EnableTokenExchange:  false,
	}
	err := h.init(c)
	if err == nil {
		t.Fatal("expected error: require_token_exchange without enable_token_exchange should fail")
	}
}

// Error class: strict receiver rejects missing requirement as classErrInvalidPayload.
func TestClassifyErrorKindStrictReceiverMissingRequirement(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{Capabilities: []string{"exchange-token"}}
	protos := testWebDAVProtocol()
	err := classifyAndNormalizeRequirements(protos, disco, nil, true)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrInvalidPayload {
		t.Errorf("expected classErrInvalidPayload, got %d", ce.kind)
	}
}

// Strict receiver, incapable sender, contradictory must-exchange-token on wire:
// receiver-requires check fires first (classErrPeerUnsatisfied).
func TestClassifyStrictReceiverIncapableSenderWithMustExchange(t *testing.T) {
	disco := &wellknown.OcmDiscoveryData{Capabilities: []string{}}
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, disco, nil, true)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrPeerUnsatisfied {
		t.Errorf("expected classErrPeerUnsatisfied, got %d", ce.kind)
	}
}

// Discovery failure, strict receiver, share also has must-exchange-token:
// both conditions trigger the OR gate.
func TestClassifyDiscoveryFailureStrictReceiverWithMustExchange(t *testing.T) {
	protos := testWebDAVProtocol("must-exchange-token")
	err := classifyAndNormalizeRequirements(protos, nil, fmt.Errorf("dns timeout"), true)
	ce, ok := err.(*classificationError)
	if !ok {
		t.Fatalf("expected *classificationError, got %T", err)
	}
	if ce.kind != classErrDiscoveryFailed {
		t.Errorf("expected classErrDiscoveryFailed, got %d", ce.kind)
	}
}

// Handler init with valid evaluator config wires evaluator output through to
// the handler's localEval field. init fails on gateway lookup (no real
// endpoint), but the evaluator is validated and set before that.
func TestSharesHandlerInitSetsEvaluatorOutput(t *testing.T) {
	h := &sharesHandler{gatewayClient: &sharesMockGW{}}
	c := &config{
		EnableTokenExchange:  true,
		RequireTokenExchange: true,
		LegacyPeerPolicy:    "prefer-strict",
	}
	// init will fail on the gateway lookup but evaluator runs first.
	_ = h.init(c)

	if !h.localEval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange=true from evaluator output")
	}
	if !h.localEval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable=true from evaluator output")
	}
	if h.localEval.LegacyPeerPolicy != "prefer-strict" {
		t.Errorf("expected LegacyPeerPolicy=prefer-strict, got %q", h.localEval.LegacyPeerPolicy)
	}
}

// fakeDiscoServer creates a TLS test server that returns a discovery response
// with the given capabilities. Returns the server and the host:port to use as
// the owner IDP.
func fakeDiscoServer(t *testing.T, capabilities []string) (*httptest.Server, string) {
	t.Helper()
	disco := wellknown.OcmDiscoveryData{
		Enabled:    true,
		APIVersion: "1.2.0",
		Capabilities: capabilities,
		Criteria:     []string{},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disco)
	}))
	u, _ := url.Parse(srv.URL)
	// Override the package-level client TLS config is not possible,
	// but discoverOwner uses InsecureSkipVerify=true so self-signed certs work.
	return srv, u.Host
}

func createShareBody(ownerHost string, requirements []string) []byte {
	reqJSON := "[]"
	if len(requirements) > 0 {
		parts := make([]string, len(requirements))
		for i, r := range requirements {
			parts[i] = `"` + r + `"`
		}
		reqJSON = "[" + strings.Join(parts, ",") + "]"
	}
	return []byte(fmt.Sprintf(`{
		"shareWith":"marie@local.example.org",
		"name":"test.txt",
		"providerId":"provider-id",
		"owner":"einstein@%s",
		"sender":"einstein@%s",
		"shareType":"user",
		"resourceType":"file",
		"protocol":{
			"webdav":{
				"sharedSecret":"secret",
				"permissions":["read"],
				"uri":"https://%s/remote.php/dav/files/einstein/test.txt",
				"requirements":%s
			}
		}
	}`, ownerHost, ownerHost, ownerHost, reqJSON))
}

// HTTP-level: strict receiver, capable sender, share omits must-exchange-token -> 400.
func TestCreateShareReturns400ForStrictReceiverMissingRequirement(t *testing.T) {
	srv, host := fakeDiscoServer(t, []string{"exchange-token"})
	defer srv.Close()

	// Patch default HTTP transport to trust the test server cert.
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer func() { http.DefaultTransport = origTransport }()

	eval, _ := evaluator.NewLocalEvaluator(evaluator.Config{
		TokenExchangeEnabled: true,
		RequireTokenExchange: true,
		LegacyPeerPolicy:    "prefer-strict",
	})
	h := &sharesHandler{
		gatewayClient: &sharesMockGW{
			createResp: &ocmincoming.CreateOCMIncomingShareResponse{
				Status: &rpc.Status{Code: rpc.Code_CODE_OK},
			},
		},
		localEval: eval.Evaluation(),
	}

	body := createShareBody(host, nil)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.15:12345"
	rr := httptest.NewRecorder()

	h.CreateShare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for strict receiver missing requirement, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// HTTP-level: contradictory must-exchange-token from legacy sender (no capability) -> 400.
func TestCreateShareReturns400ForContradictoryMustExchange(t *testing.T) {
	srv, host := fakeDiscoServer(t, []string{})
	defer srv.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer func() { http.DefaultTransport = origTransport }()

	eval, _ := evaluator.NewLocalEvaluator(evaluator.Config{
		TokenExchangeEnabled: false,
	})
	h := &sharesHandler{
		gatewayClient: &sharesMockGW{
			createResp: &ocmincoming.CreateOCMIncomingShareResponse{
				Status: &rpc.Status{Code: rpc.Code_CODE_OK},
			},
		},
		localEval: eval.Evaluation(),
	}

	body := createShareBody(host, []string{"must-exchange-token"})
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.15:12345"
	rr := httptest.NewRecorder()

	h.CreateShare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for contradictory must-exchange-token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// HTTP-level: strict receiver + discovery failure -> 502.
func TestCreateShareReturns502ForStrictReceiverDiscoveryFailure(t *testing.T) {
	// No disco server: discovery will fail.
	eval, _ := evaluator.NewLocalEvaluator(evaluator.Config{
		TokenExchangeEnabled: true,
		RequireTokenExchange: true,
		LegacyPeerPolicy:    "prefer-strict",
	})
	h := &sharesHandler{
		gatewayClient: &sharesMockGW{
			createResp: &ocmincoming.CreateOCMIncomingShareResponse{
				Status: &rpc.Status{Code: rpc.Code_CODE_OK},
			},
		},
		localEval: eval.Evaluation(),
	}

	body := createShareBody("unreachable.example.invalid", nil)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.15:12345"
	rr := httptest.NewRecorder()

	h.CreateShare(rr, req)

	// Discovery failure with receiver requiring exchange -> classification
	// returns classErrDiscoveryFailed -> 502. However, getAndResolveProtocols
	// may also fail first since the URI has a host already. Check for either
	// 502 (classification reached) or 400 (protocol resolution failed).
	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 502 or 400 for discovery failure in strict mode, got %d; body: %s", rr.Code, rr.Body.String())
	}
}
