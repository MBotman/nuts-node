/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
 */

package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/stretchr/testify/assert"
)

var actorSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var custodianSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

var actorDID = *vdr.RandomDID
var custodianDID = *vdr.AltRandomDID
var custodianDIDDocument = getCustodianDIDDocument()
var actorSigningKeyID = getActorSigningKey()
var custodianSigningKeyID = getCustodianSigningKey()

func getActorSigningKey() *did.URI {
	serviceID, _ := did.ParseURI(actorDID.String() + "#signing-key")

	return serviceID
}

func getCustodianSigningKey() *did.URI {
	keyID, _ := did.ParseURI(custodianDID.String() + "#signing-key")

	return keyID
}

func getCustodianDIDDocument() *did.Document {
	id := *vdr.AltRandomDID
	serviceID, _ := url.Parse(id.String() + "#service-id")

	doc := did.Document{
		ID: id,
	}
	signingKeyID := id
	signingKeyID.Fragment = "signing-key"
	key, err := did.NewVerificationMethod(signingKeyID, did.JsonWebKey2020, id, custodianSigningKey.Public())
	if err != nil {
		panic(err)
	}
	doc.AddAssertionMethod(key)
	doc.Service = append(doc.Service, did.Service{
		ID:   did.URI{URL: *serviceID},
		Type: "oauth",
	})
	return &doc
}

func TestAuth_CreateAccessToken(t *testing.T) {
	t.Run("invalid jwt", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "jwt bearer token validation failed")
		}
	})

	t.Run("broken identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.nameResolver.EXPECT().Resolve(actorDID).MinTimes(1).Return("foo", nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(nil, errors.New("identity validation failed"))
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("JWT validity too long", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.ExpirationKey, time.Now().Add(10*time.Second))
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "JWT validity too long")
		}
	})

	t.Run("invalid identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.nameResolver.EXPECT().Resolve(actorDID).MinTimes(1).Return("foo", nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(&contract.VPVerificationResult{Validity: contract.Invalid}, nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("valid - with legal base", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.nameResolver.EXPECT().Resolve(actorDID).MinTimes(1).Return("Nice Org", nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), custodianSigningKeyID.String()).Return("expectedAT", nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(&contract.VPVerificationResult{
			Validity:            contract.Valid,
			DisclosedAttributes: map[string]string{"name": "Henk de Vries"},
			ContractAttributes:  map[string]string{"legal_entity": "Nice Org"},
		}, nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "expectedAT", response.AccessToken)
	})
}

func TestService_validateIssuer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Resolve(actorDID).Return("OK", nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, tokenCtx.actorName, "OK")
	})
	t.Run("invalid issuer", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuerKey, "not a urn")

		err := ctx.oauthService.validateIssuer(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.issuer: input does not begin with 'did:' prefix")
		}
	})
	t.Run("unable to resolve name", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Resolve(actorDID).Return("", errors.New("failed"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: failed")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()

		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(nil, fmt.Errorf("not found"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer key ID: not found")
	})
}

func TestService_validateSubject(t *testing.T) {
	t.Run("subject managed", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)

		err := ctx.oauthService.validateSubject(tokenCtx)
		assert.NoError(t, err)
	})
	t.Run("invalid subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "not a urn")

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.subject: input does not begin with 'did:' prefix")
		}
	})
	t.Run("subject not managed by this node", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(false)

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "is not managed by this node")
		}
	})
}

func TestOAuthService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("malformed JWTs", func(t *testing.T) {
		tokenCtx := &validationContext{
			rawJwtBearerToken: "foo",
		}
		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
		assert.Equal(t, "invalid compact serialization format: invalid number of segments", err.Error())

		tokenCtx2 := &validationContext{
			rawJwtBearerToken: "123.456.787",
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx2)
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
		assert.Equal(t, "failed to parse JOSE headers: invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 512)

		keyID := "did:nuts:somedid#key-id"

		ctx.docResolver.EXPECT().ResolveSigningKey(keyID, gomock.Any()).Return(privateKey.Public(), nil)

		// alg: RS256
		token := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, keyID)
		signedToken, err := jwt.Sign(token, jwa.RS256, privateKey, jwt.WithHeaders(hdrs))
		if !assert.NoError(t, err) {
			return
		}

		tokenCtx := &validationContext{
			rawJwtBearerToken: string(signedToken),
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
		assert.Equal(t, "token signing algorithm is not supported: RS256", err.Error())
	})

	t.Run("valid token", func(t *testing.T) {
		tokenCtx := validContext()
		signToken(tokenCtx)

		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).Return(actorSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, actorDID.String(), tokenCtx.jwtBearerToken.Issuer())
	})
}

func TestOAuthService_buildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VPVerificationResult{Validity: contract.Valid},
			jwtBearerTokenClaims:       &services.NutsJwtBearerToken{},
			jwtBearerToken:             jwt.New(),
		}

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)

		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VPVerificationResult{Validity: contract.Valid},
			jwtBearerTokenClaims:       &services.NutsJwtBearerToken{},
			jwtBearerToken:             jwt.New(),
		}
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
	})

	// todo some extra tests needed for claims generation
}

func TestOAuthService_CreateJwtBearerToken(t *testing.T) {
	sid := "789"
	usi := "irma identity token"

	request := services.CreateJwtBearerTokenRequest{
		Custodian:     custodianDID.String(),
		Actor:         actorDID.String(),
		Subject:       &sid,
		IdentityToken: &usi,
	}

	t.Run("create a JwtBearerToken", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil)
		ctx.docResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("token", nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		if !assert.Nil(t, err) || !assert.NotEmpty(t, token.BearerToken) {
			t.FailNow()
		}
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("custodian without endpoint", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(&did.Document{}, nil, nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "service not found")
	})

	t.Run("request without custodian", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateJwtBearerTokenRequest{
			Actor:         actorDID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
		}

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil)
		ctx.docResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})
}

func Test_claimsFromRequest(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()
	sid := "789"
	usi := "irma identity token"

	t.Run("ok", func(t *testing.T) {
		request := services.CreateJwtBearerTokenRequest{
			Custodian:     custodianDID.String(),
			Actor:         actorDID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
		}
		audience := "aud"
		timeFunc = func() time.Time {
			return time.Unix(10, 0)
		}
		defer func() {
			timeFunc = time.Now
		}()

		claims := claimsFromRequest(request, audience)

		assert.Equal(t, audience, claims[jwt.AudienceKey])
		assert.Equal(t, int64(15), claims[jwt.ExpirationKey])
		assert.Equal(t, int64(10), claims[jwt.IssuedAtKey])
		assert.Equal(t, request.Actor, claims[jwt.IssuerKey])
		assert.Equal(t, 0, claims[jwt.NotBeforeKey])
		assert.Equal(t, request.Custodian, claims[jwt.SubjectKey])
		assert.Equal(t, *request.IdentityToken, claims["usi"])
		assert.Equal(t, *request.Subject, claims["sid"])
	})
}

func TestOAuthService_IntrospectAccessToken(t *testing.T) {

	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(true)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		claims, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		if !assert.NoError(t, err) || !assert.NotNil(t, claims) {
			t.FailNow()
		}
	})

	t.Run("private key not present", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(false)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})

	t.Run("key not present on DID", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(true)
		ctx.docResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(nil, types.ErrNotFound)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})
}

func TestAuth_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		assert.NoError(t, ctx.oauthService.Configure())
	})
}

func validContext() *validationContext {
	sid := "subject"
	usi := base64.StdEncoding.EncodeToString([]byte("irma identity token"))
	claims := services.NutsJwtBearerToken{
		UserIdentity: &usi,
		SubjectID:    &sid,
		KeyID:        actorSigningKeyID.String(),
	}
	hdrs := map[string]interface{}{
		jwt.AudienceKey:   "endpoint",
		jwt.ExpirationKey: time.Now().Add(5 * time.Second).Unix(),
		jwt.JwtIDKey:      "a005e81c-6749-4967-b01c-495228fcafb4",
		jwt.IssuedAtKey:   time.Now().UTC(),
		jwt.IssuerKey:     actorDID.String(),
		jwt.NotBeforeKey:  0,
		jwt.SubjectKey:    custodianDID.String(),
	}
	token := jwt.New()
	for k, v := range hdrs {
		if err := token.Set(k, v); err != nil {
			panic(err)
		}
	}
	return &validationContext{
		jwtBearerTokenClaims: &claims,
		jwtBearerToken:       token,
	}
}

func signToken(context *validationContext) {
	claimsAsMap, _ := context.jwtBearerTokenClaims.AsMap()
	for k, v := range claimsAsMap {
		if err := context.jwtBearerToken.Set(k, v); err != nil {
			panic(err)
		}
	}
	hdrs := jws.NewHeaders()
	err := hdrs.Set(jws.KeyIDKey, actorSigningKeyID.String())
	if err != nil {
		panic(err)
	}
	signedToken, err := jwt.Sign(context.jwtBearerToken, jwa.ES256, actorSigningKey, jwt.WithHeaders(hdrs))
	if err != nil {
		panic(err)
	}
	context.rawJwtBearerToken = string(signedToken)
}

type testContext struct {
	ctrl               *gomock.Controller
	contractClientMock *services.MockContractClient
	privateKeyStore    *crypto.MockPrivateKeyStore
	docResolver        *types.MockResolver
	nameResolver       *vdr.MockNameResolver
	oauthService       *service
}

var createContext = func(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	contractClientMock := services.NewMockContractClient(ctrl)
	privateKeyStore := crypto.NewMockPrivateKeyStore(ctrl)
	didResolver := types.NewMockResolver(ctrl)
	nameResolver := vdr.NewMockNameResolver(ctrl)
	return &testContext{
		ctrl:               ctrl,
		contractClientMock: contractClientMock,
		privateKeyStore:    privateKeyStore,
		docResolver:        didResolver,
		nameResolver:       nameResolver,
		oauthService: &service{
			didResolver:     didResolver,
			contractClient:  contractClientMock,
			privateKeyStore: privateKeyStore,
			nameResolver:    nameResolver,
		},
	}
}
