// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/types/interface.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did/did
//
// Package types is a generated GoMock package.
package types

import (
	context "context"
	crypto "crypto"
	url "net/url"
	reflect "reflect"
	time "time"

	ssi "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	crypto0 "github.com/nuts-foundation/nuts-node/crypto"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	gomock "go.uber.org/mock/gomock"
)

// MockDIDResolver is a mock of DIDResolver interface.
type MockDIDResolver struct {
	ctrl     *gomock.Controller
	recorder *MockDIDResolverMockRecorder
}

// MockDIDResolverMockRecorder is the mock recorder for MockDIDResolver.
type MockDIDResolverMockRecorder struct {
	mock *MockDIDResolver
}

// NewMockDIDResolver creates a new mock instance.
func NewMockDIDResolver(ctrl *gomock.Controller) *MockDIDResolver {
	mock := &MockDIDResolver{ctrl: ctrl}
	mock.recorder = &MockDIDResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDIDResolver) EXPECT() *MockDIDResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockDIDResolver) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockDIDResolverMockRecorder) Resolve(id, metadata any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockDIDResolver)(nil).Resolve), id, metadata)
}

// MockPredicate is a mock of Predicate interface.
type MockPredicate struct {
	ctrl     *gomock.Controller
	recorder *MockPredicateMockRecorder
}

// MockPredicateMockRecorder is the mock recorder for MockPredicate.
type MockPredicateMockRecorder struct {
	mock *MockPredicate
}

// NewMockPredicate creates a new mock instance.
func NewMockPredicate(ctrl *gomock.Controller) *MockPredicate {
	mock := &MockPredicate{ctrl: ctrl}
	mock.recorder = &MockPredicateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPredicate) EXPECT() *MockPredicateMockRecorder {
	return m.recorder
}

// Match mocks base method.
func (m *MockPredicate) Match(arg0 did.Document, arg1 DocumentMetadata) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Match", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Match indicates an expected call of Match.
func (mr *MockPredicateMockRecorder) Match(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Match", reflect.TypeOf((*MockPredicate)(nil).Match), arg0, arg1)
}

// MockDocFinder is a mock of DocFinder interface.
type MockDocFinder struct {
	ctrl     *gomock.Controller
	recorder *MockDocFinderMockRecorder
}

// MockDocFinderMockRecorder is the mock recorder for MockDocFinder.
type MockDocFinderMockRecorder struct {
	mock *MockDocFinder
}

// NewMockDocFinder creates a new mock instance.
func NewMockDocFinder(ctrl *gomock.Controller) *MockDocFinder {
	mock := &MockDocFinder{ctrl: ctrl}
	mock.recorder = &MockDocFinderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocFinder) EXPECT() *MockDocFinderMockRecorder {
	return m.recorder
}

// Find mocks base method.
func (m *MockDocFinder) Find(arg0 ...Predicate) ([]did.Document, error) {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Find", varargs...)
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Find indicates an expected call of Find.
func (mr *MockDocFinderMockRecorder) Find(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Find", reflect.TypeOf((*MockDocFinder)(nil).Find), arg0...)
}

// MockDocCreator is a mock of DocCreator interface.
type MockDocCreator struct {
	ctrl     *gomock.Controller
	recorder *MockDocCreatorMockRecorder
}

// MockDocCreatorMockRecorder is the mock recorder for MockDocCreator.
type MockDocCreatorMockRecorder struct {
	mock *MockDocCreator
}

// NewMockDocCreator creates a new mock instance.
func NewMockDocCreator(ctrl *gomock.Controller) *MockDocCreator {
	mock := &MockDocCreator{ctrl: ctrl}
	mock.recorder = &MockDocCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocCreator) EXPECT() *MockDocCreatorMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockDocCreator) Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockDocCreatorMockRecorder) Create(ctx, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocCreator)(nil).Create), ctx, options)
}

// MockDocWriter is a mock of DocWriter interface.
type MockDocWriter struct {
	ctrl     *gomock.Controller
	recorder *MockDocWriterMockRecorder
}

// MockDocWriterMockRecorder is the mock recorder for MockDocWriter.
type MockDocWriterMockRecorder struct {
	mock *MockDocWriter
}

// NewMockDocWriter creates a new mock instance.
func NewMockDocWriter(ctrl *gomock.Controller) *MockDocWriter {
	mock := &MockDocWriter{ctrl: ctrl}
	mock.recorder = &MockDocWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocWriter) EXPECT() *MockDocWriterMockRecorder {
	return m.recorder
}

// Write mocks base method.
func (m *MockDocWriter) Write(document did.Document, metadata DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", document, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockDocWriterMockRecorder) Write(document, metadata any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockDocWriter)(nil).Write), document, metadata)
}

// MockDocUpdater is a mock of DocUpdater interface.
type MockDocUpdater struct {
	ctrl     *gomock.Controller
	recorder *MockDocUpdaterMockRecorder
}

// MockDocUpdaterMockRecorder is the mock recorder for MockDocUpdater.
type MockDocUpdaterMockRecorder struct {
	mock *MockDocUpdater
}

// NewMockDocUpdater creates a new mock instance.
func NewMockDocUpdater(ctrl *gomock.Controller) *MockDocUpdater {
	mock := &MockDocUpdater{ctrl: ctrl}
	mock.recorder = &MockDocUpdaterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocUpdater) EXPECT() *MockDocUpdaterMockRecorder {
	return m.recorder
}

// Update mocks base method.
func (m *MockDocUpdater) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDocUpdaterMockRecorder) Update(ctx, id, next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDocUpdater)(nil).Update), ctx, id, next)
}

// MockKeyResolver is a mock of KeyResolver interface.
type MockKeyResolver struct {
	ctrl     *gomock.Controller
	recorder *MockKeyResolverMockRecorder
}

// MockKeyResolverMockRecorder is the mock recorder for MockKeyResolver.
type MockKeyResolverMockRecorder struct {
	mock *MockKeyResolver
}

// NewMockKeyResolver creates a new mock instance.
func NewMockKeyResolver(ctrl *gomock.Controller) *MockKeyResolver {
	mock := &MockKeyResolver{ctrl: ctrl}
	mock.recorder = &MockKeyResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyResolver) EXPECT() *MockKeyResolverMockRecorder {
	return m.recorder
}

// ResolveKey mocks base method.
func (m *MockKeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType RelationType) (ssi.URI, crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveKey", id, validAt, relationType)
	ret0, _ := ret[0].(ssi.URI)
	ret1, _ := ret[1].(crypto.PublicKey)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ResolveKey indicates an expected call of ResolveKey.
func (mr *MockKeyResolverMockRecorder) ResolveKey(id, validAt, relationType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveKey), id, validAt, relationType)
}

// ResolveKeyByID mocks base method.
func (m *MockKeyResolver) ResolveKeyByID(keyID string, validAt *time.Time, relationType RelationType) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveKeyByID", keyID, validAt, relationType)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveKeyByID indicates an expected call of ResolveKeyByID.
func (mr *MockKeyResolverMockRecorder) ResolveKeyByID(keyID, validAt, relationType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveKeyByID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveKeyByID), keyID, validAt, relationType)
}

// MockNutsKeyResolver is a mock of NutsKeyResolver interface.
type MockNutsKeyResolver struct {
	ctrl     *gomock.Controller
	recorder *MockNutsKeyResolverMockRecorder
}

// MockNutsKeyResolverMockRecorder is the mock recorder for MockNutsKeyResolver.
type MockNutsKeyResolverMockRecorder struct {
	mock *MockNutsKeyResolver
}

// NewMockNutsKeyResolver creates a new mock instance.
func NewMockNutsKeyResolver(ctrl *gomock.Controller) *MockNutsKeyResolver {
	mock := &MockNutsKeyResolver{ctrl: ctrl}
	mock.recorder = &MockNutsKeyResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNutsKeyResolver) EXPECT() *MockNutsKeyResolverMockRecorder {
	return m.recorder
}

// ResolvePublicKey mocks base method.
func (m *MockNutsKeyResolver) ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolvePublicKey", kid, sourceTransactionsRefs)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolvePublicKey indicates an expected call of ResolvePublicKey.
func (mr *MockNutsKeyResolverMockRecorder) ResolvePublicKey(kid, sourceTransactionsRefs any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolvePublicKey", reflect.TypeOf((*MockNutsKeyResolver)(nil).ResolvePublicKey), kid, sourceTransactionsRefs)
}

// MockVDR is a mock of VDR interface.
type MockVDR struct {
	ctrl     *gomock.Controller
	recorder *MockVDRMockRecorder
}

// MockVDRMockRecorder is the mock recorder for MockVDR.
type MockVDRMockRecorder struct {
	mock *MockVDR
}

// NewMockVDR creates a new mock instance.
func NewMockVDR(ctrl *gomock.Controller) *MockVDR {
	mock := &MockVDR{ctrl: ctrl}
	mock.recorder = &MockVDRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVDR) EXPECT() *MockVDRMockRecorder {
	return m.recorder
}

// ConflictedDocuments mocks base method.
func (m *MockVDR) ConflictedDocuments() ([]did.Document, []DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConflictedDocuments")
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].([]DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ConflictedDocuments indicates an expected call of ConflictedDocuments.
func (mr *MockVDRMockRecorder) ConflictedDocuments() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConflictedDocuments", reflect.TypeOf((*MockVDR)(nil).ConflictedDocuments))
}

// Create mocks base method.
func (m *MockVDR) Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockVDRMockRecorder) Create(ctx, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockVDR)(nil).Create), ctx, options)
}

// DeriveWebDIDDocument mocks base method.
func (m *MockVDR) DeriveWebDIDDocument(ctx context.Context, baseURL url.URL, nutsDID did.DID) (*did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeriveWebDIDDocument", ctx, baseURL, nutsDID)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveWebDIDDocument indicates an expected call of DeriveWebDIDDocument.
func (mr *MockVDRMockRecorder) DeriveWebDIDDocument(ctx, baseURL, nutsDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveWebDIDDocument", reflect.TypeOf((*MockVDR)(nil).DeriveWebDIDDocument), ctx, baseURL, nutsDID)
}

// IsOwner mocks base method.
func (m *MockVDR) IsOwner(arg0 context.Context, arg1 did.DID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsOwner", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsOwner indicates an expected call of IsOwner.
func (mr *MockVDRMockRecorder) IsOwner(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOwner", reflect.TypeOf((*MockVDR)(nil).IsOwner), arg0, arg1)
}

// ListOwned mocks base method.
func (m *MockVDR) ListOwned(ctx context.Context) ([]did.DID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOwned", ctx)
	ret0, _ := ret[0].([]did.DID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOwned indicates an expected call of ListOwned.
func (mr *MockVDRMockRecorder) ListOwned(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOwned", reflect.TypeOf((*MockVDR)(nil).ListOwned), ctx)
}

// Resolver mocks base method.
func (m *MockVDR) Resolver() DIDResolver {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolver")
	ret0, _ := ret[0].(DIDResolver)
	return ret0
}

// Resolver indicates an expected call of Resolver.
func (mr *MockVDRMockRecorder) Resolver() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolver", reflect.TypeOf((*MockVDR)(nil).Resolver))
}

// Update mocks base method.
func (m *MockVDR) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockVDRMockRecorder) Update(ctx, id, next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockVDR)(nil).Update), ctx, id, next)
}

// MockDocumentOwner is a mock of DocumentOwner interface.
type MockDocumentOwner struct {
	ctrl     *gomock.Controller
	recorder *MockDocumentOwnerMockRecorder
}

// MockDocumentOwnerMockRecorder is the mock recorder for MockDocumentOwner.
type MockDocumentOwnerMockRecorder struct {
	mock *MockDocumentOwner
}

// NewMockDocumentOwner creates a new mock instance.
func NewMockDocumentOwner(ctrl *gomock.Controller) *MockDocumentOwner {
	mock := &MockDocumentOwner{ctrl: ctrl}
	mock.recorder = &MockDocumentOwnerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocumentOwner) EXPECT() *MockDocumentOwnerMockRecorder {
	return m.recorder
}

// IsOwner mocks base method.
func (m *MockDocumentOwner) IsOwner(arg0 context.Context, arg1 did.DID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsOwner", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsOwner indicates an expected call of IsOwner.
func (mr *MockDocumentOwnerMockRecorder) IsOwner(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOwner", reflect.TypeOf((*MockDocumentOwner)(nil).IsOwner), arg0, arg1)
}

// ListOwned mocks base method.
func (m *MockDocumentOwner) ListOwned(ctx context.Context) ([]did.DID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOwned", ctx)
	ret0, _ := ret[0].([]did.DID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOwned indicates an expected call of ListOwned.
func (mr *MockDocumentOwnerMockRecorder) ListOwned(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOwned", reflect.TypeOf((*MockDocumentOwner)(nil).ListOwned), ctx)
}

// MockDocManipulator is a mock of DocManipulator interface.
type MockDocManipulator struct {
	ctrl     *gomock.Controller
	recorder *MockDocManipulatorMockRecorder
}

// MockDocManipulatorMockRecorder is the mock recorder for MockDocManipulator.
type MockDocManipulatorMockRecorder struct {
	mock *MockDocManipulator
}

// NewMockDocManipulator creates a new mock instance.
func NewMockDocManipulator(ctrl *gomock.Controller) *MockDocManipulator {
	mock := &MockDocManipulator{ctrl: ctrl}
	mock.recorder = &MockDocManipulatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocManipulator) EXPECT() *MockDocManipulatorMockRecorder {
	return m.recorder
}

// AddVerificationMethod mocks base method.
func (m *MockDocManipulator) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", ctx, id, keyUsage)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) AddVerificationMethod(ctx, id, keyUsage any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).AddVerificationMethod), ctx, id, keyUsage)
}

// Deactivate mocks base method.
func (m *MockDocManipulator) Deactivate(ctx context.Context, id did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocManipulatorMockRecorder) Deactivate(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocManipulator)(nil).Deactivate), ctx, id)
}

// RemoveVerificationMethod mocks base method.
func (m *MockDocManipulator) RemoveVerificationMethod(ctx context.Context, id, keyID did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveVerificationMethod", ctx, id, keyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveVerificationMethod indicates an expected call of RemoveVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) RemoveVerificationMethod(ctx, id, keyID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).RemoveVerificationMethod), ctx, id, keyID)
}

// MockServiceResolver is a mock of ServiceResolver interface.
type MockServiceResolver struct {
	ctrl     *gomock.Controller
	recorder *MockServiceResolverMockRecorder
}

// MockServiceResolverMockRecorder is the mock recorder for MockServiceResolver.
type MockServiceResolverMockRecorder struct {
	mock *MockServiceResolver
}

// NewMockServiceResolver creates a new mock instance.
func NewMockServiceResolver(ctrl *gomock.Controller) *MockServiceResolver {
	mock := &MockServiceResolver{ctrl: ctrl}
	mock.recorder = &MockServiceResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServiceResolver) EXPECT() *MockServiceResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockServiceResolver) Resolve(query ssi.URI, maxDepth int) (did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", query, maxDepth)
	ret0, _ := ret[0].(did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockServiceResolverMockRecorder) Resolve(query, maxDepth any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockServiceResolver)(nil).Resolve), query, maxDepth)
}

// ResolveEx mocks base method.
func (m *MockServiceResolver) ResolveEx(endpoint ssi.URI, depth, maxDepth int, documentCache map[string]*did.Document) (did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveEx", endpoint, depth, maxDepth, documentCache)
	ret0, _ := ret[0].(did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveEx indicates an expected call of ResolveEx.
func (mr *MockServiceResolverMockRecorder) ResolveEx(endpoint, depth, maxDepth, documentCache any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveEx", reflect.TypeOf((*MockServiceResolver)(nil).ResolveEx), endpoint, depth, maxDepth, documentCache)
}
