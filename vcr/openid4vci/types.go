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

// This file defines types specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

package openid4vci

import (
	ssi "github.com/nuts-foundation/go-did"
	"time"
)

// PreAuthorizedCodeGrant is the grant type used for pre-authorized code grant from the OpenID4VCI specification.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow
const PreAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// WalletMetadataWellKnownPath defines the well-known path for OpenID4VCI Wallet Metadata.
// It is NOT specified by the OpenID4VCI specification, we just use it to be consistent with the other well-known paths.
const WalletMetadataWellKnownPath = "/.well-known/openid-credential-wallet"

// ProviderMetadataWellKnownPath defines the well-known path for retrieving OpenID ProviderMetadata
// Specified by https://www.rfc-editor.org/rfc/rfc8414.html#section-3
const ProviderMetadataWellKnownPath = "/.well-known/oauth-authorization-server"

// CredentialIssuerMetadataWellKnownPath defines the well-known path for retrieving OpenID4VCI CredentialIssuerMetadata
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-
const CredentialIssuerMetadataWellKnownPath = "/.well-known/openid-credential-issuer"

// VerifiableCredentialJSONLDFormat defines the JSON-LD format identifier for Verifiable Credentials.
const VerifiableCredentialJSONLDFormat = "ldp_vc"

// JWTTypeOpenID4VCIProof defines the OpenID4VCI JWT-subtype (used as typ claim in the JWT).
const JWTTypeOpenID4VCIProof = "openid4vci-proof+jwt"

// ProofTypeJWT defines the Credential Request proof type for JWTs.
const ProofTypeJWT = "jwt"

// CredentialOfferStatus defines the status of a credential offer flow.
type CredentialOfferStatus string

// CredentialOfferStatusReceived indicates that the wallet has received the credential.
const CredentialOfferStatusReceived CredentialOfferStatus = "credential_received"

// CredentialIssuerMetadata defines the OpenID4VCI Credential Issuer Metadata.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
type CredentialIssuerMetadata struct {
	// CredentialIssuer defines the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialEndpoint defines where the wallet can send a request to retrieve a credential.
	CredentialEndpoint string `json:"credential_endpoint"`

	// CredentialsSupported defines metadata about which credential types the credential issuer can issue.
	CredentialsSupported []map[string]interface{} `json:"credentials_supported"`
}

// OAuth2ClientMetadata defines the OAuth2 Client Metadata, extended with OpenID4VCI parameters.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata.
type OAuth2ClientMetadata struct {
	// CredentialOfferEndpoint defines URL of the verifiable credential wallet's offer endpoint
	CredentialOfferEndpoint string `json:"credential_offer_endpoint"`
}

// ProviderMetadata defines the OpenID Connect Provider metadata.
// Specified by https://www.rfc-editor.org/rfc/rfc8414.txt
type ProviderMetadata struct {
	// Issuer defines the authorization server's identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	Issuer string `json:"issuer"`

	// TokenEndpoint defines the URL of the authorization server's token endpoint [RFC6749].
	TokenEndpoint string `json:"token_endpoint"`

	// PreAuthorizedGrantAnonymousAccessSupported indicates whether anonymous access (requests without client_id)
	// for pre-authorized code grant flows.
	// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv
	PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported"`
}

// CredentialOffer defines credentials offered by the issuer to the wallet.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
type CredentialOffer struct {
	// CredentialIssuer defines the identifier of the credential issuer.
	CredentialIssuer string `json:"credential_issuer"`
	// Credentials defines the credentials offered by the issuer to the wallet.
	Credentials []OfferedCredential `json:"credentials"`
	// Grants defines the grants offered by the issuer to the wallet.
	Grants map[string]interface{} `json:"grants"`
}

// OfferedCredential defines a single entry in the credentials array of a CredentialOffer. We currently do not support 'JSON string' offers.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
// and https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-secured-using-data-integ
type OfferedCredential struct {
	// Format specifies the credential format.
	Format string `json:"format"`
	// CredentialDefinition contains the 'credential_definition' for the Verifiable Credential Format flows.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

// CredentialDefinition defines the 'credential_definition' for Format VerifiableCredentialJSONLDFormat
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-secured-using-data-integ
type CredentialDefinition struct {
	Context           []ssi.URI               `json:"@context"`
	Type              []ssi.URI               `json:"type"`
	CredentialSubject *map[string]interface{} `json:"credentialSubject,omitempty"` // optional and currently not used
}

// CredentialOfferResponse defines the response for credential offer requests.
// It is an extension to the OpenID4VCI specification to better support server-to-server issuance.
type CredentialOfferResponse struct {
	// Status defines the status of the credential offer.
	Status CredentialOfferStatus `json:"status"`
}

// CredentialRequest defines the credential request sent by the wallet to the issuer.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request.
type CredentialRequest struct {
	Format               string                  `json:"format"`
	CredentialDefinition *CredentialDefinition   `json:"credential_definition,omitempty"`
	Proof                *CredentialRequestProof `json:"proof,omitempty"`
}

// CredentialRequestProof defines the proof of possession of key material when requesting a Credential.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
type CredentialRequestProof struct {
	Jwt       string `json:"jwt"`
	ProofType string `json:"proof_type"`
}

// CredentialResponse defines the response for credential requests.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialResponse struct {
	Format     string                  `json:"format,omitempty"`
	Credential *map[string]interface{} `json:"credential,omitempty"`
	CNonce     *string                 `json:"c_nonce,omitempty"`
}

// TokenResponse defines the response for OAuth2 access token requests, extended with OpenID4VCI parameters.
// Specified by https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response
type TokenResponse struct {
	// AccessToken defines the access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// CNonce defines the JSON string containing a nonce to be used to create a proof of possession of key material when requesting a Credential.
	// When received, the WalletAPIClient MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.
	// Although optional in the spec, we use a concrete value since we always fill it.
	CNonce string `json:"c_nonce,omitempty"`

	// ExpiresIn defines the lifetime in seconds of the access token.
	// Although optional in the spec, we use a concrete value since we always fill it.
	ExpiresIn int `json:"expires_in,omitempty"`

	// TokenType defines the type of the token issued as described in [RFC6749].
	TokenType string `json:"token_type"`
}

// Config holds the config for the OpenID4VCI credential issuer and wallet
type Config struct {
	// DefinitionsDIR defines the directory where the additional credential definitions are stored
	DefinitionsDIR string `koanf:"definitionsdir"`
	// Enabled indicates if issuing and receiving credentials over OpenID4VCI is enabled
	Enabled bool `koanf:"enabled"`
	// Timeout defines the timeout for HTTP client operations
	Timeout time.Duration `koanf:"timeout"`
}
