// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/issuer/openid.go
//
// Generated by this command:
//
//	mockgen -destination=vcr/issuer/openid_mock.go -package=issuer -source=vcr/issuer/openid.go
//
// Package issuer is a generated GoMock package.
package issuer

import (
	context "context"
	reflect "reflect"

	vc "github.com/nuts-foundation/go-did/vc"
	openid4vci "github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	gomock "go.uber.org/mock/gomock"
)

// MockOpenIDHandler is a mock of OpenIDHandler interface.
type MockOpenIDHandler struct {
	ctrl     *gomock.Controller
	recorder *MockOpenIDHandlerMockRecorder
}

// MockOpenIDHandlerMockRecorder is the mock recorder for MockOpenIDHandler.
type MockOpenIDHandlerMockRecorder struct {
	mock *MockOpenIDHandler
}

// NewMockOpenIDHandler creates a new mock instance.
func NewMockOpenIDHandler(ctrl *gomock.Controller) *MockOpenIDHandler {
	mock := &MockOpenIDHandler{ctrl: ctrl}
	mock.recorder = &MockOpenIDHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOpenIDHandler) EXPECT() *MockOpenIDHandlerMockRecorder {
	return m.recorder
}

// HandleAccessTokenRequest mocks base method.
func (m *MockOpenIDHandler) HandleAccessTokenRequest(ctx context.Context, preAuthorizedCode string) (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleAccessTokenRequest", ctx, preAuthorizedCode)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// HandleAccessTokenRequest indicates an expected call of HandleAccessTokenRequest.
func (mr *MockOpenIDHandlerMockRecorder) HandleAccessTokenRequest(ctx, preAuthorizedCode any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleAccessTokenRequest", reflect.TypeOf((*MockOpenIDHandler)(nil).HandleAccessTokenRequest), ctx, preAuthorizedCode)
}

// HandleCredentialRequest mocks base method.
func (m *MockOpenIDHandler) HandleCredentialRequest(ctx context.Context, request openid4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleCredentialRequest", ctx, request, accessToken)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HandleCredentialRequest indicates an expected call of HandleCredentialRequest.
func (mr *MockOpenIDHandlerMockRecorder) HandleCredentialRequest(ctx, request, accessToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleCredentialRequest", reflect.TypeOf((*MockOpenIDHandler)(nil).HandleCredentialRequest), ctx, request, accessToken)
}

// Metadata mocks base method.
func (m *MockOpenIDHandler) Metadata() openid4vci.CredentialIssuerMetadata {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Metadata")
	ret0, _ := ret[0].(openid4vci.CredentialIssuerMetadata)
	return ret0
}

// Metadata indicates an expected call of Metadata.
func (mr *MockOpenIDHandlerMockRecorder) Metadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Metadata", reflect.TypeOf((*MockOpenIDHandler)(nil).Metadata))
}

// OfferCredential mocks base method.
func (m *MockOpenIDHandler) OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletIdentifier string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OfferCredential", ctx, credential, walletIdentifier)
	ret0, _ := ret[0].(error)
	return ret0
}

// OfferCredential indicates an expected call of OfferCredential.
func (mr *MockOpenIDHandlerMockRecorder) OfferCredential(ctx, credential, walletIdentifier any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OfferCredential", reflect.TypeOf((*MockOpenIDHandler)(nil).OfferCredential), ctx, credential, walletIdentifier)
}

// ProviderMetadata mocks base method.
func (m *MockOpenIDHandler) ProviderMetadata() openid4vci.ProviderMetadata {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProviderMetadata")
	ret0, _ := ret[0].(openid4vci.ProviderMetadata)
	return ret0
}

// ProviderMetadata indicates an expected call of ProviderMetadata.
func (mr *MockOpenIDHandlerMockRecorder) ProviderMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProviderMetadata", reflect.TypeOf((*MockOpenIDHandler)(nil).ProviderMetadata))
}
