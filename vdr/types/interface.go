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

package types

import (
	"context"
	"crypto"
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"net/url"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
)

// DIDResolver is the interface for DID resolvers: the process of getting the backing document of a DID.
type DIDResolver interface {
	// Resolve returns a DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata
	// It returns ErrDeactivated if the DID Document has been deactivated and metadata is unset or metadata.AllowDeactivated is false.
	// It returns ErrNoActiveController if all of the DID Documents controllers have been deactivated and metadata is unset or metadata.AllowDeactivated is false.
	Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error)
}

// Predicate is an interface for abstracting search options on DID documents
type Predicate interface {
	// Match returns true if the given DID Document passes the predicate condition
	Match(did.Document, DocumentMetadata) bool
}

// DocFinder is the interface that groups all methods for finding DID documents based on search conditions
type DocFinder interface {
	Find(...Predicate) ([]did.Document, error)
}

// DocCreator is the interface that wraps the Create method
type DocCreator interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated.
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto2.Key, error)
}

// DocWriter is the interface that groups al the DID Document write methods
type DocWriter interface {
	// Write writes a DID Document.
	// Returns ErrDIDAlreadyExists when DID already exists
	// When a document already exists, the Update should be used instead
	Write(document did.Document, metadata DocumentMetadata) error
}

// DocUpdater is the interface that defines functions that alter the state of a DID document
type DocUpdater interface {
	// Update replaces the DID document identified by DID with the nextVersion
	// If the DID Document is not found, ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	Update(ctx context.Context, id did.DID, next did.Document) error
}

// KeyResolver is the interface for resolving keys.
// This can be used for checking if a signing key is valid at a point in time or to just find a valid key for signing.
type KeyResolver interface {
	// ResolveKeyByID looks up a specific key of the given RelationType and returns it as crypto.PublicKey.
	// If multiple keys are valid, the first one is returned.
	// An ErrKeyNotFound is returned when no key (of the specified type) is found.
	ResolveKeyByID(keyID string, validAt *time.Time, relationType RelationType) (crypto.PublicKey, error)
	// ResolveKey looks for a valid key of the given RelationType for the given DID, and returns its ID and the key itself.
	// If multiple keys are valid, the first one is returned.
	// An ErrKeyNotFound is returned when no key (of the specified type) is found.
	ResolveKey(id did.DID, validAt *time.Time, relationType RelationType) (ssi.URI, crypto.PublicKey, error)
}

// NutsSigningKeyType defines the verification method relationship type for signing keys in Nuts DID Documents.
const NutsSigningKeyType = AssertionMethod

// NutsKeyResolver is the interface for resolving keys from Nuts DID Documents,
// supporting Nuts-specific DID resolution parameters.
type NutsKeyResolver interface {
	// ResolvePublicKey loads the key from a DID Document where the DID Document
	// was created with one of the given tx refs
	// It returns ErrKeyNotFound when the key could not be found in the DID Document.
	// It returns ErrNotFound when the DID Document can't be found.
	ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error)
}

// DocIterator is the function type for iterating over the all current DID Documents in the store
type DocIterator func(doc did.Document, metadata DocumentMetadata) error

// VDR defines the public end facing methods for the Verifiable Data Registry.
type VDR interface {
	DocumentOwner
	DocCreator
	DocUpdater

	// Resolver returns the resolver for getting the DID document for a DID.
	Resolver() DIDResolver

	// ConflictedDocuments returns the DID Document and metadata of all documents with a conflict.
	ConflictedDocuments() ([]did.Document, []DocumentMetadata, error)

	// DeriveWebDIDDocument returns the did:web equivalent of the given Nuts DID. If it doesn't exist or is not owned by this node it returns an error.
	DeriveWebDIDDocument(ctx context.Context, baseURL url.URL, nutsDID did.DID) (*did.Document, error)
}

// DocumentOwner is the interface for checking DID document ownership (presence of private keys).
type DocumentOwner interface {
	// IsOwner returns true if the DID Document is owned by the node, meaning there are private keys present for the DID Document.
	IsOwner(context.Context, did.DID) (bool, error)
	// ListOwned returns all the DIDs owned by the node.
	ListOwned(ctx context.Context) ([]did.DID, error)
}

// DocManipulator groups several higher level methods to alter the state of a DID document.
type DocManipulator interface {
	// Deactivate deactivates a DID document
	// Deactivation will be done in such a way that a DID doc cannot be used / activated anymore.
	// Since the deactivation is definitive, no version is required
	// If the DID Document is not found ErrNotFound is returned
	// If the DID Document is not managed by this node, ErrDIDNotManagedByThisNode is returned
	// If the DID Document is already deactivated ErrDeactivated is returned
	Deactivate(ctx context.Context, id did.DID) error

	// RemoveVerificationMethod removes a VerificationMethod from a DID document.
	// It accepts the id DID as identifier for the DID document.
	// It accepts the kid DID as identifier for the VerificationMethod.
	// It returns an ErrNotFound when the DID document could not be found.
	// It returns an ErrNotFound when there is no VerificationMethod with the provided kid in the document.
	// It returns an ErrDeactivated when the DID document has the deactivated state.
	// It returns an ErrDIDNotManagedByThisNode if the DID document is not managed by this node.
	RemoveVerificationMethod(ctx context.Context, id, keyID did.DID) error

	// AddVerificationMethod generates a new key and adds it, wrapped as a VerificationMethod, to a DID document.
	// It accepts a DID as identifier for the DID document.
	// It returns an ErrNotFound when the DID document could not be found.
	// It returns an ErrDeactivated when the DID document has the deactivated state.
	// It returns an ErrDIDNotManagedByThisNode if the DID document is not managed by this node.
	AddVerificationMethod(ctx context.Context, id did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error)
}

// ErrDIDMethodNotSupported is returned when a DID method is not supported by the DID resolver
var ErrDIDMethodNotSupported = errors.New("DID method not supported")

// RelationType is the type that contains the different possible relationships between a DID Document and a VerificationMethod
// They are defined in the DID spec: https://www.w3.org/TR/did-core/#verification-relationships
type RelationType uint

const (
	Authentication       RelationType = iota
	AssertionMethod      RelationType = iota
	KeyAgreement         RelationType = iota
	CapabilityInvocation RelationType = iota
	CapabilityDelegation RelationType = iota
)

// ServiceResolver allows looking up DID document services, following references.
type ServiceResolver interface {
	// Resolve looks up the DID document of the specified query and then tries to find the service with the specified type.
	// The query must be in the form of a service query, e.g. `did:nuts:12345/serviceEndpoint?type=some-type`.
	// The maxDepth indicates how deep references are followed. If maxDepth = 0, no references are followed (and an error is returned if the given query resolves to a reference).
	// If the DID document or service is not found, a reference can't be resolved or the references exceed maxDepth, an error is returned.
	Resolve(query ssi.URI, maxDepth int) (did.Service, error)

	// ResolveEx tries to resolve a DID service from the given endpoint URI, following references (URIs that begin with 'did:').
	// When the endpoint is a reference it resolves it up until the (per spec) max reference depth. When resolving a reference it recursively calls itself with depth + 1.
	// The documentCache map is used to avoid resolving the same document over and over again, which might be a (slightly more) expensive operation.
	ResolveEx(endpoint ssi.URI, depth int, maxDepth int, documentCache map[string]*did.Document) (did.Service, error)
}
