// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/didnuts/didstore/interface.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/didnuts/didstore/mock.go -package=didstore -source=vdr/didnuts/didstore/interface.go
//
// Package didstore is a generated GoMock package.
package didstore

import (
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	types "github.com/nuts-foundation/nuts-node/vdr/types"
	gomock "go.uber.org/mock/gomock"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockStore) Add(didDocument did.Document, transaction Transaction) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", didDocument, transaction)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockStoreMockRecorder) Add(didDocument, transaction any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockStore)(nil).Add), didDocument, transaction)
}

// Conflicted mocks base method.
func (m *MockStore) Conflicted(fn types.DocIterator) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Conflicted", fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// Conflicted indicates an expected call of Conflicted.
func (mr *MockStoreMockRecorder) Conflicted(fn any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Conflicted", reflect.TypeOf((*MockStore)(nil).Conflicted), fn)
}

// ConflictedCount mocks base method.
func (m *MockStore) ConflictedCount() (uint, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConflictedCount")
	ret0, _ := ret[0].(uint)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConflictedCount indicates an expected call of ConflictedCount.
func (mr *MockStoreMockRecorder) ConflictedCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConflictedCount", reflect.TypeOf((*MockStore)(nil).ConflictedCount))
}

// DocumentCount mocks base method.
func (m *MockStore) DocumentCount() (uint, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DocumentCount")
	ret0, _ := ret[0].(uint)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DocumentCount indicates an expected call of DocumentCount.
func (mr *MockStoreMockRecorder) DocumentCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DocumentCount", reflect.TypeOf((*MockStore)(nil).DocumentCount))
}

// Iterate mocks base method.
func (m *MockStore) Iterate(fn types.DocIterator) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Iterate", fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// Iterate indicates an expected call of Iterate.
func (mr *MockStoreMockRecorder) Iterate(fn any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Iterate", reflect.TypeOf((*MockStore)(nil).Iterate), fn)
}

// Resolve mocks base method.
func (m *MockStore) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*types.DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockStoreMockRecorder) Resolve(id, metadata any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockStore)(nil).Resolve), id, metadata)
}
