/*
 * Copyright (C) 2022 Nuts community
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

// Package didservice contains DID Document related functionality that only matters to the current node.
// All functionality here has zero relations to the network.
package didservice

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"sort"
	"sync"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DefaultMaxServiceReferenceDepth holds the default max. allowed depth for DID service references.
const DefaultMaxServiceReferenceDepth = 5

var _ types.DIDResolver = &DIDResolverRouter{}

// DIDResolverRouter is a DID resolver that can route to different DID resolvers based on the DID method
type DIDResolverRouter struct {
	resolvers sync.Map
}

// Resolve looks up the right resolver for the given DID and delegates the resolution to it.
// If no resolver is registered for the given DID method, ErrDIDMethodNotSupported is returned.
func (r *DIDResolverRouter) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	method := id.Method
	resolver, registered := r.resolvers.Load(method)
	if !registered {
		return nil, nil, types.ErrDIDMethodNotSupported
	}
	return resolver.(types.DIDResolver).Resolve(id, metadata)
}

// Register registers a DID resolver for the given DID method.
func (r *DIDResolverRouter) Register(method string, resolver types.DIDResolver) {
	r.resolvers.Store(method, resolver)
}

var _ types.KeyResolver = KeyResolver{}

// KeyResolver implements the KeyResolver interface that uses keys from resolved DIDs.
type KeyResolver struct {
	Resolver types.DIDResolver
}

func (r KeyResolver) ResolveKeyByID(keyID string, validAt *time.Time, relationType types.RelationType) (crypto.PublicKey, error) {
	holder, err := GetDIDFromURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	doc, _, err := r.Resolver.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return nil, err
	}
	relationships, err := resolveRelationships(doc, relationType)
	if err != nil {
		return nil, err
	}
	for _, rel := range relationships {
		if rel.ID.String() == keyID {
			return rel.PublicKey()
		}
	}
	return nil, types.ErrKeyNotFound
}

func (r KeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType types.RelationType) (ssi.URI, crypto.PublicKey, error) {
	keys, err := resolveKeys(r.Resolver, id, validAt, relationType)
	if err != nil {
		return ssi.URI{}, nil, err
	}
	if len(keys) == 0 {
		return ssi.URI{}, nil, types.ErrKeyNotFound
	}
	publicKey, err := keys[0].PublicKey()
	if err != nil {
		return ssi.URI{}, nil, err
	}
	return keys[0].ID.URI(), publicKey, nil
}

func resolveKeys(didResolver types.DIDResolver, id did.DID, validAt *time.Time, relationType types.RelationType) ([]did.VerificationRelationship, error) {
	var docs []*did.Document
	doc, _, err := didResolver.Resolve(id, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return nil, err
	}
	docs = append(docs, doc)
	// did:web of a Nuts node is probably a derivative of a did:nuts to which it refers to using alsoKnownAs,
	// so if that's the case we need to resolve those as well, since the keys are stored under their did:nuts ID, not did:web.
	if doc.ID.Method == "web" && len(doc.AlsoKnownAs) > 0 {
		for _, aka := range doc.AlsoKnownAs {
			akaDID, _ := did.ParseDID(aka.String())
			if akaDID == nil {
				// alsoKnownAs is not a DID
				continue
			}
			if akaDID.Method != "nuts" {
				// Just to be sure, only support did:nuts alsoKnownAs for now. Otherwise, we might end up in an infinite loop?
				continue
			}
			akaDoc, _, err := didResolver.Resolve(*akaDID, &types.ResolveMetadata{ResolveTime: validAt, AllowDeactivated: false})
			if err != nil && !IsFunctionalResolveError(err) {
				// Ignore unresolvable alsoKnownAs documents
				return nil, fmt.Errorf("failed to resolve alsoKnownAs (did=%s, alsoKnownAs=%s): %w", id, akaDID, err)
			}
			if akaDoc != nil {
				docs = append(docs, akaDoc)
			}
		}
	}
	var allKeys []did.VerificationRelationship
	for _, doc := range docs {
		docKeys, err := resolveRelationships(doc, relationType)
		if err != nil {
			return nil, err
		}
		allKeys = append(allKeys, docKeys...)
	}
	return allKeys, nil
}

func resolveRelationships(doc *did.Document, relationType types.RelationType) (relationships did.VerificationRelationships, err error) {
	switch relationType {
	case types.Authentication:
		return doc.Authentication, nil
	case types.AssertionMethod:
		return doc.AssertionMethod, nil
	case types.KeyAgreement:
		return doc.KeyAgreement, nil
	case types.CapabilityInvocation:
		return doc.CapabilityInvocation, nil
	case types.CapabilityDelegation:
		return doc.CapabilityDelegation, nil
	default:
		return nil, fmt.Errorf("unable to locate RelationType %v", relationType)
	}
}

// ServiceResolver is a wrapper around a DID store that allows resolving services, following references.
type ServiceResolver struct {
	Resolver types.DIDResolver
}

func (s ServiceResolver) Resolve(query ssi.URI, maxDepth int) (did.Service, error) {
	return s.ResolveEx(query, 0, maxDepth, map[string]*did.Document{})
}

func (s ServiceResolver) ResolveEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error) {
	if depth >= maxDepth {
		return did.Service{}, types.ErrServiceReferenceToDeep
	}

	referencedDID, err := GetDIDFromURL(endpoint.String())
	if err != nil {
		// Shouldn't happen, because only DID URLs are passed?
		return did.Service{}, err
	}
	var document *did.Document
	if document = documentCache[referencedDID.String()]; document == nil {
		document, _, err = s.Resolver.Resolve(referencedDID, nil)
		if err != nil {
			return did.Service{}, err
		}
		documentCache[referencedDID.String()] = document
	}

	var service *did.Service
	for _, curr := range document.Service {
		if curr.Type == endpoint.Query().Get(serviceTypeQueryParameter) {
			// If there are multiple services with the same type the document is conflicted.
			// This can happen temporarily during a service update (delete old, add new).
			// Both endpoints are likely to be active in the timeframe that the conflict exists, so picking the first entry is preferred for availability over an error.
			service = &curr
			break
		}
	}
	if service == nil {
		return did.Service{}, types.ErrServiceNotFound
	}

	var endpointURL string
	if service.UnmarshalServiceEndpoint(&endpointURL) == nil {
		// Service endpoint is a string, if it's a reference we need to resolve it
		if IsServiceReference(endpointURL) {
			// Looks like a reference, recurse
			resolvedEndpointURI, err := ssi.ParseURI(endpointURL)
			if err != nil {
				return did.Service{}, err
			}
			err = ValidateServiceReference(*resolvedEndpointURI)
			if err != nil {
				return did.Service{}, err
			}
			return s.ResolveEx(*resolvedEndpointURI, depth+1, maxDepth, documentCache)
		}
	}
	return *service, nil
}

// PrivateKeyResolver resolves private keys based upon the VDR document resolver
type PrivateKeyResolver struct {
	DIDResolver     types.DIDResolver
	PrivKeyResolver nutsCrypto.KeyResolver
}

// ResolvePrivateKey is a tries to find a private key in the node's keystore for the given DID, of the given type.
// Special treatment is given to did:web DIDs, which are assumed to be a derivative of a did:nuts DID:
// It will try to return a private key from the did:nuts document, as long as it's present (given it's public key fingerprint)
// in the did:web document (since the caller requested a did:web key, not a did:nuts one).
// If no private key is found, ErrKeyNotFound is returned.
func (r PrivateKeyResolver) ResolvePrivateKey(ctx context.Context, id did.DID, validAt *time.Time, relationType types.RelationType) (nutsCrypto.Key, error) {
	keys, err := resolveKeys(r.DIDResolver, id, validAt, relationType)
	if err != nil {
		return nil, err
	}
	// Optimization: give precedence to did:nuts keys, since those are most likely to be present (in contrary to did:web)
	// Sort keys by DID method, so did:nuts keys are first
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].ID.Method == "nuts" {
			return true
		}
		return false
	})
	for _, key := range keys {
		privateKey, err := r.PrivKeyResolver.Resolve(ctx, key.ID.String())
		if err != nil {
			if errors.Is(err, nutsCrypto.ErrPrivateKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("failed to resolve private key (kid=%s): %w", key.ID, err)
		}
		if id.Method == "web" && key.ID.Method == "nuts" {
			// did:web is a derivative of did:nuts, match with key on did:web method since it's an alias of the did:nuts key.
			for _, candidate := range keys {
				if candidate.ID.WithoutURL().Equals(id) && // check it's a key from the requested DID
					candidate.PublicKeyBase58 == key.PublicKeyBase58 {
					return nutsCrypto.Alias(privateKey, candidate.ID.String()), nil
				}
			}
		}
		// Otherwise, just return the key
		return privateKey, nil
	}
	// No keys were found
	return nil, types.ErrKeyNotFound
}

// IsFunctionalResolveError returns true if the given error indicates the DID or service not being found or invalid,
// e.g. because it is deactivated, referenced too deeply, etc.
func IsFunctionalResolveError(target error) bool {
	return errors.Is(target, types.ErrNotFound) ||
		errors.Is(target, types.ErrDeactivated) ||
		errors.Is(target, types.ErrServiceNotFound) ||
		errors.Is(target, types.ErrNoActiveController) ||
		errors.Is(target, types.ErrServiceReferenceToDeep) ||
		errors.Is(target, did.InvalidDIDErr) ||
		errors.As(target, new(ServiceQueryError))
}
