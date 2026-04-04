// Copyright 2018-2024 CERN
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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	gateway "github.com/cs3org/go-cs3apis/cs3/gateway/v1beta1"
	types "github.com/cs3org/go-cs3apis/cs3/types/v1beta1"
	"github.com/pkg/errors"

	userpb "github.com/cs3org/go-cs3apis/cs3/identity/user/v1beta1"
	ocmincoming "github.com/cs3org/go-cs3apis/cs3/ocm/incoming/v1beta1"
	ocmprovider "github.com/cs3org/go-cs3apis/cs3/ocm/provider/v1beta1"
	ocm "github.com/cs3org/go-cs3apis/cs3/sharing/ocm/v1beta1"

	rpc "github.com/cs3org/go-cs3apis/cs3/rpc/v1beta1"
	"github.com/cs3org/reva/v3/internal/http/services/reqres"
	"github.com/cs3org/reva/v3/internal/http/services/wellknown"
	"github.com/cs3org/reva/v3/pkg/appctx"
	"github.com/cs3org/reva/v3/pkg/errtypes"
	"github.com/cs3org/reva/v3/pkg/ocm/evaluator"
	"github.com/cs3org/reva/v3/pkg/rgrpc/todo/pool"
	"github.com/cs3org/reva/v3/pkg/utils"
	"github.com/go-playground/validator/v10"
	"github.com/studio-b12/gowebdav"
)

var validate = validator.New()

type sharesHandler struct {
	gatewayClient              gateway.GatewayAPIClient
	exposeRecipientDisplayName bool
	localEval                  evaluator.LocalEvaluation
}

func (h *sharesHandler) init(c *config) error {
	eval, err := evaluator.NewLocalEvaluator(evaluator.Config{
		TokenExchangeEnabled: c.EnableTokenExchange,
		RequireTokenExchange: c.RequireTokenExchange,
		LegacyPeerPolicy:    c.LegacyPeerPolicy,
	})
	if err != nil {
		return err
	}
	h.localEval = eval.Evaluation()
	h.exposeRecipientDisplayName = c.ExposeRecipientDisplayName

	h.gatewayClient, err = pool.GetGatewayServiceClient(pool.Endpoint(c.GatewaySvc))
	if err != nil {
		return err
	}
	return nil
}

// CreateShare implements the OCM /shares call and stores an incoming share
func (h *sharesHandler) CreateShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := appctx.GetLogger(ctx)
	req, err := getCreateShareRequest(r)
	// Log whitelist metadata only; incoming OCM share requests carry shared secrets in protocol options.
	logEvent := log.Info().Str("remote", r.RemoteAddr).Err(err)
	if req != nil {
		logEvent = logEvent.Str("sender", req.Sender).Str("resource_type", req.ResourceType)
	}
	logEvent.Msg("OCM /shares request received")
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorInvalidParameter, err.Error(), nil)
		return
	}

	sender, err := GetUserIdFromOCMAddress(req.Sender)
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorInvalidParameter, "error with remote sender", err)
		return
	}

	// TODO(lopresti) here we extract the client IP from the request, but in case
	// of a proxied request we should rather extract it from X-Forwarded-For or similar headers,
	// or remove this logic altogether and rely on signed requests as per OCM standard
	clientIP, err := utils.GetClientIP(r)
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorServerError, fmt.Sprintf("error retrieving client IP from request: %s", r.RemoteAddr), err)
		return
	}
	providerInfo := ocmprovider.ProviderInfo{
		Domain: sender.Idp,
		Services: []*ocmprovider.Service{
			{
				Host: clientIP,
			},
		},
	}
	providerAllowedResp, err := h.gatewayClient.IsProviderAllowed(ctx, &ocmprovider.IsProviderAllowedRequest{
		Provider: &providerInfo,
	})
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorServerError, "error sending a grpc isProviderAllowed request", err)
		return
	}
	if providerAllowedResp.Status.Code != rpc.Code_CODE_OK {
		reqres.WriteError(w, r, reqres.APIErrorUnauthenticated, "provider not authorized", errors.New(providerAllowedResp.Status.Message))
		return
	}

	shareWith, err := GetUserIdFromOCMAddress(req.ShareWith)
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorInvalidParameter, "error with shareWith user", err)
		return
	}

	userRes, err := h.gatewayClient.GetUser(ctx, &userpb.GetUserRequest{
		UserId: &userpb.UserId{OpaqueId: shareWith.OpaqueId}, SkipFetchingUserGroups: true,
	})
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorServerError, "error searching recipient", err)
		return
	}
	if userRes.Status.Code != rpc.Code_CODE_OK {
		reqres.WriteError(w, r, reqres.APIErrorNotFound, "user not found", errors.New(userRes.Status.Message))
		return
	}

	owner, err := GetUserIdFromOCMAddress(req.Owner)
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorInvalidParameter, "error with remote owner", err)
		return
	}

	// Single discovery call for both URI resolution and receiver-side classification.
	disco, discoveryErr := discoverOwner(ctx, owner.Idp)
	if discoveryErr != nil {
		log.Warn().Err(discoveryErr).Str("owner_idp", owner.Idp).Msg("owner discovery failed")
	}

	protocols, legacy, err := getAndResolveProtocols(ctx, req.Protocols, owner.Idp, disco)
	if err != nil || len(protocols) == 0 {
		reqres.WriteError(w, r, reqres.APIErrorInvalidParameter, "error with protocols payload", err)
		return
	}

	if err := classifyAndNormalizeRequirements(protocols, disco, discoveryErr, h.localEval.RequiresTokenExchange); err != nil {
		apiCode := reqres.APIErrorServerError
		if ce, ok := err.(*classificationError); ok {
			switch ce.kind {
			case classErrInvalidPayload, classErrPeerUnsatisfied:
				apiCode = reqres.APIErrorInvalidParameter
			case classErrDiscoveryFailed:
				apiCode = reqres.APIErrorProviderError
			}
		}
		reqres.WriteError(w, r, apiCode, "receiver classification failed", err)
		return
	}

	if legacy && req.ResourceType == "file" {
		// in case of legacy OCM v1.0 shares, we have to PROPFIND the remote resource to check the type,
		// because remote systems such as Nextcloud may send "file" even if the resource is a folder.
		c := gowebdav.NewClient(protocols[0].GetWebdavOptions().Uri, "", "")
		c.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(protocols[0].GetWebdavOptions().SharedSecret+":")))
		target, err := c.Stat("")
		if err != nil {
			log.Info().Err(err).Str("endpoint", protocols[0].GetWebdavOptions().Uri).Msg("error stating remote resource, assuming file")
		} else if target.IsDir() {
			req.ResourceType = "folder"
		}
	}

	createShareReq := &ocmincoming.CreateOCMIncomingShareRequest{
		Description:        req.Description,
		Name:               req.Name,
		ResourceId:         req.ProviderID,
		Owner:              owner,
		Sender:             sender,
		ShareWith:          userRes.User.Id,
		SharedResourceType: getResourceTypeFromOCMRequest(req.ResourceType),
		RecipientType:      getOCMShareType(req.ShareType),
		Protocols:          protocols,
	}

	if req.Expiration != 0 {
		createShareReq.Expiration = &types.Timestamp{
			Seconds: req.Expiration,
		}
	}

	log.Info().Str("resource_id", req.ProviderID).Str("sender", req.Sender).Str("resource_type", req.ResourceType).Msg("CreateOCMIncomingShare payload")
	createShareResp, err := h.gatewayClient.CreateOCMIncomingShare(ctx, createShareReq)
	if err != nil {
		reqres.WriteError(w, r, reqres.APIErrorServerError, "error creating ocm share", err)
		return
	}

	if createShareResp.Status.Code != rpc.Code_CODE_OK {
		// TODO: define errors in the cs3apis
		reqres.WriteError(w, r, reqres.APIErrorServerError, "error creating ocm share", errors.New(createShareResp.Status.Message))
		return
	}

	response := map[string]any{}
	if h.exposeRecipientDisplayName {
		response["recipientDisplayName"] = userRes.User.DisplayName
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func getCreateShareRequest(r *http.Request) (*NewShareRequest, error) {
	var req NewShareRequest
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && contentType == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, errors.Wrap(err, "malformed OCM /shares request")
		}
	} else {
		return nil, errors.New("malformed OCM /shares request payload")
	}
	// validate the request
	if err := validate.Struct(req); err != nil {
		return nil, err
	}
	// Protocols are interface-backed, so validate the decoded protocol payloads
	// explicitly before we create or persist a received share.
	if err := req.Protocols.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

func getResourceTypeFromOCMRequest(t string) ocm.SharedResourceType {
	switch t {
	case "file":
		return ocm.SharedResourceType_SHARE_RESOURCE_TYPE_FILE
	case "folder":
		return ocm.SharedResourceType_SHARE_RESOURCE_TYPE_CONTAINER
	case "embedded":
		return ocm.SharedResourceType_SHARE_RESOURCE_TYPE_EMBEDDED
	default:
		return ocm.SharedResourceType_SHARE_RESOURCE_TYPE_INVALID
	}
}

func getOCMShareType(st string) ocm.RecipientType {
	switch st {
	case "user":
		return ocm.RecipientType_RECIPIENT_TYPE_USER
	case "group":
		return ocm.RecipientType_RECIPIENT_TYPE_GROUP
	default:
		// for now assume user share if not provided
		return ocm.RecipientType_RECIPIENT_TYPE_USER
	}
}

// discoverOwner performs a single OCM discovery against owner.Idp and returns the
// full response so callers can use it for both URI resolution and classification.
// Known pre-existing concern: TLS verification is disabled (insecure=true).
func discoverOwner(ctx context.Context, ownerServer string) (*wellknown.OcmDiscoveryData, error) {
	log := appctx.GetLogger(ctx)
	ocmClient := NewClient(time.Duration(10)*time.Second, true)
	disco, err := ocmClient.Discover(ctx, "https://"+ownerServer)
	if err != nil {
		log.Warn().Str("sender", ownerServer).Err(err).Msg("failed to discover OCM owner")
		return nil, err
	}
	return disco, nil
}

func getAndResolveProtocols(ctx context.Context, p Protocols, ownerServer string, disco *wellknown.OcmDiscoveryData) (protos []*ocm.Protocol, legacy bool, err error) {
	protos = make([]*ocm.Protocol, 0, len(p))
	legacy = false
	for _, data := range p {
		var uri string
		ocmProto := data.ToOCMProtocol()
		protocolName := GetProtocolName(data)
		switch protocolName {
		case "webdav":
			uri = ocmProto.GetWebdavOptions().Uri
		case "webapp":
			uri = ocmProto.GetWebappOptions().Uri
		case "embedded":
			protos = append(protos, ocmProto)
			continue
		}
		if err := validateProtocolURI(protocolName, uri); err != nil {
			return nil, false, err
		}

		u, _ := url.Parse(uri)
		if u.Host != "" {
			protos = append(protos, ocmProto)
			continue
		}

		if disco == nil {
			var derr error
			disco, derr = discoverOwner(ctx, ownerServer)
			if derr != nil {
				return nil, false, derr
			}
		}
		remoteRoot, err := resolveProtoRoot(disco, protocolName)
		if err != nil {
			return nil, false, err
		}
		if strings.HasPrefix(uri, "/") {
			ru, _ := url.Parse(remoteRoot)
			ru.Path = uri
			uri = ru.String()
		} else if uri == "" {
			uri = remoteRoot
			legacy = true
		} else {
			uri, _ = url.JoinPath(remoteRoot, uri)
		}

		switch protocolName {
		case "webdav":
			ocmProto.GetWebdavOptions().Uri = uri
		case "webapp":
			ocmProto.GetWebappOptions().Uri = uri
		}
		protos = append(protos, ocmProto)
	}

	return protos, legacy, nil
}

func resolveProtoRoot(disco *wellknown.OcmDiscoveryData, proto string) (string, error) {
	for _, t := range disco.ResourceTypes {
		protoRoot, ok := t.Protocols[proto]
		if ok {
			u, _ := url.Parse(disco.Endpoint)
			u.Path = protoRoot
			u.RawQuery = ""
			return u.String(), nil
		}
	}
	return "", errtypes.NotFound(fmt.Sprintf("root not found on OCM discovery for protocol %s", proto))
}

// hasCapability checks if an OCM discovery response advertises a given capability.
func hasCapability(disco *wellknown.OcmDiscoveryData, cap string) bool {
	for _, c := range disco.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// internalExchangeCapableMarker is a server-side-only marker stored in WebDAV
// requirements. It MUST NOT be accepted from the wire or added to
// validWebDAVRequirements.
const internalExchangeCapableMarker = "__exchange-token-capable"

// classificationError wraps classification failures with a category so the
// caller can map them to the appropriate OCM response code.
type classificationError struct {
	kind classificationErrorKind
	msg  string
	err  error
}

type classificationErrorKind int

const (
	classErrInvalidPayload  classificationErrorKind = iota // sender protocol violation (400)
	classErrPeerUnsatisfied                                // receiver policy cannot be met (400)
	classErrDiscoveryFailed                                // upstream discovery unavailable (502)
)

func (e *classificationError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

func (e *classificationError) Unwrap() error { return e.err }

// classifyAndNormalizeRequirements enforces receiver-side token exchange
// policy on each incoming WebDAV protocol. It rewrites the protocol
// requirements list in place so downstream storage (received/ocm.go) can
// make access decisions without re-discovering the sender.
//
// Two inputs drive the decision:
//
// 1. receiverRequiresExchange: OUR "token-exchange" criteria. When true,
//    we require code flow for all inbound shares. Per spec (IETF-RFC.md
//    Criteria section): "Shares that do not include must-exchange-token
//    in their protocol.webdav.requirements will be rejected."
//
// 2. The sender's "exchange-token" capability: whether the sender can
//    host a tokenEndPoint. Without it, no code flow is possible and any
//    must-exchange-token on the wire is contradictory.
//
// When discovery fails, shares that carry must-exchange-token are
// rejected (we cannot verify the sender's capability); all others are
// accepted as plain bearer.
func classifyAndNormalizeRequirements(protocols []*ocm.Protocol, disco *wellknown.OcmDiscoveryData, discoveryErr error, receiverRequiresExchange bool) error {
	for _, p := range protocols {
		dav, ok := p.Term.(*ocm.Protocol_WebdavOptions)
		if !ok {
			continue
		}
		reqs := dav.WebdavOptions.Requirements

		// Never trust the internal marker from the wire; it is only added
		// server-side. The primary gate is validWebDAVRequirements in specs.go;
		// this is a defense-in-depth strip.
		reqs = stripRequirement(reqs, internalExchangeCapableMarker)

		hasMustExchange := containsRequirement(reqs, "must-exchange-token")

		if discoveryErr != nil {
			if hasMustExchange || receiverRequiresExchange {
				return &classificationError{
					kind: classErrDiscoveryFailed,
					msg:  "discovery failed and token exchange is required",
					err:  discoveryErr,
				}
			}
			dav.WebdavOptions.Requirements = reqs
			continue
		}

		senderSupportsExchange := hasCapability(disco, "exchange-token")

		if !senderSupportsExchange {
			if receiverRequiresExchange {
				return &classificationError{
					kind: classErrPeerUnsatisfied,
					msg:  "receiver requires token-exchange but sender lacks exchange-token capability",
				}
			}
			if hasMustExchange {
				return &classificationError{
					kind: classErrInvalidPayload,
					msg:  "share requires must-exchange-token but sender lacks exchange-token capability",
				}
			}
			// No capability, no requirement: plain legacy share.
			dav.WebdavOptions.Requirements = reqs
			continue
		}

		// Sender has exchange-token capability. Now apply receiver policy.
		switch {
		case receiverRequiresExchange:
			// We advertise token-exchange in criteria. The spec says
			// shares without must-exchange-token "will be rejected".
			// The sender MUST have discovered our criteria and included
			// the requirement; if it did not, reject.
			if !hasMustExchange {
				return &classificationError{
					kind: classErrInvalidPayload,
					msg:  "receiver requires token-exchange but share omits must-exchange-token",
				}
			}
		case hasMustExchange:
			// This specific share explicitly requires exchange and the
			// sender can honour it. Keep the requirement as-is.
		default:
			// The sender supports exchange but neither we nor this share
			// demands it. Tag for opportunistic exchange: the storage
			// layer will try code flow first and fall back to plain
			// bearer if it fails.
			reqs = append(reqs, internalExchangeCapableMarker)
		}

		dav.WebdavOptions.Requirements = reqs
	}
	return nil
}

func containsRequirement(reqs []string, r string) bool {
	for _, v := range reqs {
		if v == r {
			return true
		}
	}
	return false
}

func stripRequirement(reqs []string, r string) []string {
	out := make([]string, 0, len(reqs))
	for _, v := range reqs {
		if v != r {
			out = append(out, v)
		}
	}
	return out
}
