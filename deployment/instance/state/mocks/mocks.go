// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/cloudfoundry/bosh-init/deployment/instance/state (interfaces: BuilderFactory,Builder,State)

package mocks

import (
	gomock "code.google.com/p/gomock/gomock"
	agentclient "github.com/cloudfoundry/bosh-agent/agentclient"
	applyspec "github.com/cloudfoundry/bosh-agent/agentclient/applyspec"
	blobstore "github.com/cloudfoundry/bosh-init/blobstore"
	state "github.com/cloudfoundry/bosh-init/deployment/instance/state"
	manifest "github.com/cloudfoundry/bosh-init/deployment/manifest"
	ui "github.com/cloudfoundry/bosh-init/ui"
)

// Mock of BuilderFactory interface
type MockBuilderFactory struct {
	ctrl     *gomock.Controller
	recorder *_MockBuilderFactoryRecorder
}

// Recorder for MockBuilderFactory (not exported)
type _MockBuilderFactoryRecorder struct {
	mock *MockBuilderFactory
}

func NewMockBuilderFactory(ctrl *gomock.Controller) *MockBuilderFactory {
	mock := &MockBuilderFactory{ctrl: ctrl}
	mock.recorder = &_MockBuilderFactoryRecorder{mock}
	return mock
}

func (_m *MockBuilderFactory) EXPECT() *_MockBuilderFactoryRecorder {
	return _m.recorder
}

func (_m *MockBuilderFactory) NewBuilder(_param0 blobstore.Blobstore, _param1 agentclient.AgentClient) state.Builder {
	ret := _m.ctrl.Call(_m, "NewBuilder", _param0, _param1)
	ret0, _ := ret[0].(state.Builder)
	return ret0
}

func (_mr *_MockBuilderFactoryRecorder) NewBuilder(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "NewBuilder", arg0, arg1)
}

// Mock of Builder interface
type MockBuilder struct {
	ctrl     *gomock.Controller
	recorder *_MockBuilderRecorder
}

// Recorder for MockBuilder (not exported)
type _MockBuilderRecorder struct {
	mock *MockBuilder
}

func NewMockBuilder(ctrl *gomock.Controller) *MockBuilder {
	mock := &MockBuilder{ctrl: ctrl}
	mock.recorder = &_MockBuilderRecorder{mock}
	return mock
}

func (_m *MockBuilder) EXPECT() *_MockBuilderRecorder {
	return _m.recorder
}

func (_m *MockBuilder) Build(_param0 string, _param1 int, _param2 manifest.Manifest, _param3 ui.Stage) (state.State, error) {
	ret := _m.ctrl.Call(_m, "Build", _param0, _param1, _param2, _param3)
	ret0, _ := ret[0].(state.State)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockBuilderRecorder) Build(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Build", arg0, arg1, arg2, arg3)
}

// Mock of State interface
type MockState struct {
	ctrl     *gomock.Controller
	recorder *_MockStateRecorder
}

// Recorder for MockState (not exported)
type _MockStateRecorder struct {
	mock *MockState
}

func NewMockState(ctrl *gomock.Controller) *MockState {
	mock := &MockState{ctrl: ctrl}
	mock.recorder = &_MockStateRecorder{mock}
	return mock
}

func (_m *MockState) EXPECT() *_MockStateRecorder {
	return _m.recorder
}

func (_m *MockState) CompiledPackages() []state.PackageRef {
	ret := _m.ctrl.Call(_m, "CompiledPackages")
	ret0, _ := ret[0].([]state.PackageRef)
	return ret0
}

func (_mr *_MockStateRecorder) CompiledPackages() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CompiledPackages")
}

func (_m *MockState) NetworkInterfaces() []state.NetworkRef {
	ret := _m.ctrl.Call(_m, "NetworkInterfaces")
	ret0, _ := ret[0].([]state.NetworkRef)
	return ret0
}

func (_mr *_MockStateRecorder) NetworkInterfaces() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "NetworkInterfaces")
}

func (_m *MockState) RenderedJobListArchive() state.BlobRef {
	ret := _m.ctrl.Call(_m, "RenderedJobListArchive")
	ret0, _ := ret[0].(state.BlobRef)
	return ret0
}

func (_mr *_MockStateRecorder) RenderedJobListArchive() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RenderedJobListArchive")
}

func (_m *MockState) RenderedJobs() []state.JobRef {
	ret := _m.ctrl.Call(_m, "RenderedJobs")
	ret0, _ := ret[0].([]state.JobRef)
	return ret0
}

func (_mr *_MockStateRecorder) RenderedJobs() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RenderedJobs")
}

func (_m *MockState) ToApplySpec() applyspec.ApplySpec {
	ret := _m.ctrl.Call(_m, "ToApplySpec")
	ret0, _ := ret[0].(applyspec.ApplySpec)
	return ret0
}

func (_mr *_MockStateRecorder) ToApplySpec() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ToApplySpec")
}
