/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package holder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// OpenIDHandler is the interface for handling issuer operations using OpenID4VCI.
type OpenIDHandler interface {
	// Metadata returns the OAuth2 client metadata for the wallet.
	Metadata() oidc4vci.OAuth2ClientMetadata
	// HandleCredentialOffer handles a credential offer from an issuer.
	// It will try to retrieve the offered credential and store it.
	HandleCredentialOffer(ctx context.Context, offer oidc4vci.CredentialOffer) error
}

var nowFunc = time.Now
var _ OpenIDHandler = (*openidHandler)(nil)

// NewOpenIDHandler creates an OpenIDHandler that tries to retrieve offered credentials, to store it in the given credential store.
func NewOpenIDHandler(config oidc4vci.ClientConfig, did did.DID, identifier string, credentialStore vcrTypes.Writer, signer crypto.JWTSigner, resolver vdr.KeyResolver, jsonldReader jsonld.Reader) OpenIDHandler {
	return &openidHandler{
		did:                 did,
		identifier:          identifier,
		credentialStore:     credentialStore,
		signer:              signer,
		resolver:            resolver,
		config:              config,
		issuerClientCreator: oidc4vci.NewIssuerAPIClient,
		jsonldReader:        jsonldReader,
	}
}

type openidHandler struct {
	did                 did.DID
	identifier          string
	credentialStore     vcrTypes.Writer
	signer              crypto.JWTSigner
	resolver            vdr.KeyResolver
	issuerClientCreator func(ctx context.Context, httpClient core.HTTPRequestDoer, credentialIssuerIdentifier string) (oidc4vci.IssuerAPIClient, error)
	jsonldReader        jsonld.Reader
	config              oidc4vci.ClientConfig
}

func (h openidHandler) Metadata() oidc4vci.OAuth2ClientMetadata {
	return oidc4vci.OAuth2ClientMetadata{
		CredentialOfferEndpoint: core.JoinURLPaths(h.identifier, "/wallet/oidc4vci/credential_offer"),
	}
}

// HandleCredentialOffer handles a credential offer from an issuer.
// Error responses on the Credential Offer Endpoint are not defined in the OpenID4VCI spec,
// so these are inferred of whatever makes sense.
func (h openidHandler) HandleCredentialOffer(ctx context.Context, offer oidc4vci.CredentialOffer) error {
	// TODO: This check is too simplistic, there can be multiple credential offers,
	//       but the issuer should only request the one it's interested in.
	//       See https://github.com/nuts-foundation/nuts-node/issues/2049
	if len(offer.Credentials) != 1 {
		return oidc4vci.Error{
			Err:        errors.New("there must be exactly 1 credential in credential offer"),
			Code:       oidc4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}
	if err := validateOfferedCredential(offer.Credentials[0]); err != nil {
		return err
	}
	credentialDefinition := offer.Credentials[0]["credential_definition"].(map[string]interface{})

	preAuthorizedCode := getPreAuthorizedCodeFromOffer(offer)
	if preAuthorizedCode == "" {
		return oidc4vci.Error{
			Err:        errors.New("couldn't find (valid) pre-authorized code grant in credential offer"),
			Code:       oidc4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = h.config.TLS
	httpClient := core.NewStrictHTTPClient(h.config.HTTPSOnly, &http.Client{
		Timeout:   h.config.Timeout,
		Transport: httpTransport,
	})
	issuerClient, err := h.issuerClientCreator(ctx, httpClient, offer.CredentialIssuer)
	if err != nil {
		return oidc4vci.Error{
			Err:        fmt.Errorf("unable to create issuer client: %w", err),
			Code:       oidc4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}

	accessTokenResponse, err := issuerClient.RequestAccessToken(oidc4vci.PreAuthorizedCodeGrant, map[string]string{
		"pre-authorized_code": preAuthorizedCode,
	})
	if err != nil {
		return oidc4vci.Error{
			Err:        fmt.Errorf("unable to request access token: %w", err),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	if accessTokenResponse.AccessToken == "" {
		return oidc4vci.Error{
			Err:        errors.New("access_token is missing"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	if accessTokenResponse.CNonce == "" {
		return oidc4vci.Error{
			Err:        errors.New("c_nonce is missing"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusInternalServerError,
		}
	}

	retrieveCtx := audit.Context(ctx, "app-openid4vci", "VCR/OpenID4VCI", "RetrieveCredential")
	retrieveCtx, cancel := context.WithTimeout(retrieveCtx, h.config.Timeout)
	defer cancel()
	credential, err := h.retrieveCredential(retrieveCtx, issuerClient, credentialDefinition, accessTokenResponse)
	if err != nil {
		return oidc4vci.Error{
			Err:        fmt.Errorf("unable to retrieve credential: %w", err),
			Code:       oidc4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}
	if err = oidc4vci.CredentialTypesMatchDefinition(h.jsonldReader, *credential, credentialDefinition); err != nil {
		return oidc4vci.Error{
			Err:        fmt.Errorf("received credential does not match offer: %w", err),
			Code:       oidc4vci.ServerError,
			StatusCode: http.StatusInternalServerError,
		}
	}
	log.Logger().
		WithField("credentialID", credential.ID).
		Infof("Received VC over OIDC4VCI")
	err = h.credentialStore.StoreCredential(*credential, nil)
	if err != nil {
		return fmt.Errorf("unable to store credential: %w", err)
	}
	return nil
}

func validateOfferedCredential(offer map[string]interface{}) error {
	// currently only supports ldp_vc
	if offer["format"] != oidc4vci.VerifiableCredentialJSONLDFormat {
		return oidc4vci.Error{
			Err:        fmt.Errorf("unsupported credential format '%s'", offer["format"]),
			Code:       oidc4vci.UnsupportedCredentialFormat,
			StatusCode: http.StatusInternalServerError,
		}
	}

	// credential_definition: REQUIRED. JSON object containing (and isolating) the detailed description of the credential type.
	credentialDefinition, ok := offer["credential_definition"].(map[string]interface{})
	if !ok {
		return oidc4vci.Error{
			Err:        errors.New("invalid or missing credential_definition"),
			Code:       oidc4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	// @context: REQUIRED. JSON array as defined in [VC_DATA_MODEL 1.0]
	if _, ok = credentialDefinition["@context"]; !ok {
		return oidc4vci.Error{
			Err:        errors.New("invalid credential_definition: missing '@context'"),
			Code:       oidc4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	// type: REQUIRED. JSON array designating the types a certain credential type supports as defined in [VC_DATA_MODEL 1.0]
	if _, ok = credentialDefinition["type"]; !ok {
		return oidc4vci.Error{
			Err:        errors.New("invalid credential_definition: missing 'type'"),
			Code:       oidc4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	// should only contain '@context' and 'type'
	// TODO: is this check too strict?
	if len(credentialDefinition) != 2 {
		return oidc4vci.Error{
			Err:        errors.New("invalid credential_definition: must contain exactly '@context' and 'type'"),
			Code:       oidc4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	return nil
}

func getPreAuthorizedCodeFromOffer(offer oidc4vci.CredentialOffer) string {
	params, ok := offer.Grants[oidc4vci.PreAuthorizedCodeGrant].(map[string]interface{})
	if !ok {
		return ""
	}
	preAuthorizedCode, ok := params["pre-authorized_code"].(string)
	if !ok {
		return ""
	}
	return preAuthorizedCode
}

func (h openidHandler) retrieveCredential(ctx context.Context, issuerClient oidc4vci.IssuerAPIClient, credentialDefinition map[string]any, tokenResponse *oidc4vci.TokenResponse) (*vc.VerifiableCredential, error) {
	keyID, err := h.resolver.ResolveSigningKeyID(h.did, nil)
	headers := map[string]interface{}{
		"typ": oidc4vci.JWTTypeOpenID4VCIProof, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": keyID,                           // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
	}
	claims := map[string]interface{}{
		"aud":   issuerClient.Metadata().CredentialIssuer,
		"iat":   nowFunc().Unix(),
		"nonce": tokenResponse.CNonce,
	}

	proof, err := h.signer.SignJWT(ctx, claims, headers, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to sign request proof: %w", err)
	}

	credentialRequest := oidc4vci.CredentialRequest{
		CredentialDefinition: &credentialDefinition,
		Format:               oidc4vci.VerifiableCredentialJSONLDFormat,
		Proof: &oidc4vci.CredentialRequestProof{
			Jwt:       proof,
			ProofType: "jwt",
		},
	}
	return issuerClient.RequestCredential(ctx, credentialRequest, tokenResponse.AccessToken)
}
