// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package lifecycle

import (
	"context"
	"testing"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
)

type fakeMachineService struct {
	resumeCalled   bool
	snapshotCalled bool
	restoreCalled  bool
}

func (fake *fakeMachineService) Create(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Start(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Pause(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Stop(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Update(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Delete(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Get(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) List(context.Context, *machinev1alpha1.MachineList) (*machinev1alpha1.MachineList, error) {
	return &machinev1alpha1.MachineList{}, nil
}

func (fake *fakeMachineService) Watch(context.Context, *machinev1alpha1.Machine) (chan *machinev1alpha1.Machine, chan error, error) {
	return make(chan *machinev1alpha1.Machine), make(chan error), nil
}

func (fake *fakeMachineService) Logs(context.Context, *machinev1alpha1.Machine) (chan string, chan error, error) {
	return make(chan string), make(chan error), nil
}

func (fake *fakeMachineService) Resume(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fake.resumeCalled = true
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Snapshot(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fake.snapshotCalled = true
	return &machinev1alpha1.Machine{}, nil
}

func (fake *fakeMachineService) Restore(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fake.restoreCalled = true
	return &machinev1alpha1.Machine{}, nil
}

func TestLifecycleAdapter_UsesDriverCapabilitiesWhenAvailable(t *testing.T) {
	service := &fakeMachineService{}
	adapter := Adapt(service)
	ctx := context.Background()

	if _, err := adapter.Resume(ctx, &machinev1alpha1.Machine{}); err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if !service.resumeCalled {
		t.Fatalf("expected resume capability to be called")
	}

	if _, err := adapter.Snapshot(ctx, &machinev1alpha1.Machine{}); err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if !service.snapshotCalled {
		t.Fatalf("expected snapshot capability to be called")
	}

	if _, err := adapter.Restore(ctx, &machinev1alpha1.Machine{}); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if !service.restoreCalled {
		t.Fatalf("expected restore capability to be called")
	}
}

func TestLifecycleAdapter_SnapshotRestoreFlow(t *testing.T) {
	service := &fakeMachineService{}
	adapter := Adapt(service)
	ctx := context.Background()
	machine := &machinev1alpha1.Machine{}

	if _, err := adapter.Snapshot(ctx, machine); err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if _, err := adapter.Restore(ctx, machine); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	if !service.snapshotCalled {
		t.Fatalf("expected snapshot to be invoked")
	}
	if !service.restoreCalled {
		t.Fatalf("expected restore to be invoked")
	}
}

type baseOnlyMachineService struct{}

func (baseOnlyMachineService) Create(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Start(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Pause(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Stop(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Update(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Delete(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) Get(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return &machinev1alpha1.Machine{}, nil
}
func (baseOnlyMachineService) List(context.Context, *machinev1alpha1.MachineList) (*machinev1alpha1.MachineList, error) {
	return &machinev1alpha1.MachineList{}, nil
}
func (baseOnlyMachineService) Watch(context.Context, *machinev1alpha1.Machine) (chan *machinev1alpha1.Machine, chan error, error) {
	return make(chan *machinev1alpha1.Machine), make(chan error), nil
}
func (baseOnlyMachineService) Logs(context.Context, *machinev1alpha1.Machine) (chan string, chan error, error) {
	return make(chan string), make(chan error), nil
}

func TestLifecycleAdapter_ReturnsUnsupportedForMissingCapabilities(t *testing.T) {
	service := &baseOnlyMachineService{}
	adapter := Adapt(service)

	if _, err := adapter.Snapshot(context.Background(), &machinev1alpha1.Machine{}); err == nil {
		t.Fatalf("expected unsupported snapshot error")
	}

	if _, err := adapter.Resume(context.Background(), &machinev1alpha1.Machine{}); err == nil {
		t.Fatalf("expected unsupported resume error")
	}

	if _, err := adapter.Restore(context.Background(), &machinev1alpha1.Machine{}); err == nil {
		t.Fatalf("expected unsupported restore error")
	}
}
