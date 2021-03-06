// Code generated by MockGen. DO NOT EDIT.
// Source: ../algorithm.go

// Package mock is a generated GoMock package.
package mock

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockAlgorithm is a mock of Algorithm interface.
type MockAlgorithm struct {
	ctrl     *gomock.Controller
	recorder *MockAlgorithmMockRecorder
}

// MockAlgorithmMockRecorder is the mock recorder for MockAlgorithm.
type MockAlgorithmMockRecorder struct {
	mock *MockAlgorithm
}

// NewMockAlgorithm creates a new mock instance.
func NewMockAlgorithm(ctrl *gomock.Controller) *MockAlgorithm {
	mock := &MockAlgorithm{ctrl: ctrl}
	mock.recorder = &MockAlgorithmMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAlgorithm) EXPECT() *MockAlgorithmMockRecorder {
	return m.recorder
}

// Name mocks base method.
func (m *MockAlgorithm) Name() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Name indicates an expected call of Name.
func (mr *MockAlgorithmMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockAlgorithm)(nil).Name))
}

// Sign mocks base method.
func (m *MockAlgorithm) Sign(data []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", data)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockAlgorithmMockRecorder) Sign(data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockAlgorithm)(nil).Sign), data)
}

// Verify mocks base method.
func (m *MockAlgorithm) Verify(data, signature []byte) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", data, signature)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockAlgorithmMockRecorder) Verify(data, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockAlgorithm)(nil).Verify), data, signature)
}

// Size mocks base method.
func (m *MockAlgorithm) Size() (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Size")
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Size indicates an expected call of Size.
func (mr *MockAlgorithmMockRecorder) Size() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Size", reflect.TypeOf((*MockAlgorithm)(nil).Size))
}
