// Code generated by MockGen. DO NOT EDIT.
// Source: crypto/storage/spi/interface.go
//
// Generated by this command:
//
//	mockgen -destination=crypto/storage/spi/mock.go -package spi -source=crypto/storage/spi/interface.go
//
// Package spi is a generated GoMock package.
package spi

import (
	context "context"
	crypto "crypto"
	reflect "reflect"

	core "github.com/nuts-foundation/nuts-node/core"
	gomock "go.uber.org/mock/gomock"
)

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// CheckHealth mocks base method.
func (m *MockStorage) CheckHealth() map[string]core.Health {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckHealth")
	ret0, _ := ret[0].(map[string]core.Health)
	return ret0
}

// CheckHealth indicates an expected call of CheckHealth.
func (mr *MockStorageMockRecorder) CheckHealth() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckHealth", reflect.TypeOf((*MockStorage)(nil).CheckHealth))
}

// GetPrivateKey mocks base method.
func (m *MockStorage) GetPrivateKey(ctx context.Context, kid string) (crypto.Signer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrivateKey", ctx, kid)
	ret0, _ := ret[0].(crypto.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPrivateKey indicates an expected call of GetPrivateKey.
func (mr *MockStorageMockRecorder) GetPrivateKey(ctx, kid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrivateKey", reflect.TypeOf((*MockStorage)(nil).GetPrivateKey), ctx, kid)
}

// ListPrivateKeys mocks base method.
func (m *MockStorage) ListPrivateKeys(ctx context.Context) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPrivateKeys", ctx)
	ret0, _ := ret[0].([]string)
	return ret0
}

// ListPrivateKeys indicates an expected call of ListPrivateKeys.
func (mr *MockStorageMockRecorder) ListPrivateKeys(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPrivateKeys", reflect.TypeOf((*MockStorage)(nil).ListPrivateKeys), ctx)
}

// Name mocks base method.
func (m *MockStorage) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockStorageMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockStorage)(nil).Name))
}

// PrivateKeyExists mocks base method.
func (m *MockStorage) PrivateKeyExists(ctx context.Context, kid string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateKeyExists", ctx, kid)
	ret0, _ := ret[0].(bool)
	return ret0
}

// PrivateKeyExists indicates an expected call of PrivateKeyExists.
func (mr *MockStorageMockRecorder) PrivateKeyExists(ctx, kid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateKeyExists", reflect.TypeOf((*MockStorage)(nil).PrivateKeyExists), ctx, kid)
}

// SavePrivateKey mocks base method.
func (m *MockStorage) SavePrivateKey(ctx context.Context, kid string, key crypto.PrivateKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SavePrivateKey", ctx, kid, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SavePrivateKey indicates an expected call of SavePrivateKey.
func (mr *MockStorageMockRecorder) SavePrivateKey(ctx, kid, key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SavePrivateKey", reflect.TypeOf((*MockStorage)(nil).SavePrivateKey), ctx, kid, key)
}
