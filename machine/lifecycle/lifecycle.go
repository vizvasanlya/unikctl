// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package lifecycle

import (
	"context"
	"errors"
	"fmt"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
)

var ErrUnsupported = errors.New("machine lifecycle operation is not supported by driver")

// MachineLifecycle defines explicit machine lifecycle transitions for platform drivers.
type MachineLifecycle interface {
	Create(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Start(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Pause(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Resume(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Snapshot(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Restore(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Stop(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Destroy(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
	Inspect(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
}

type resumeCapable interface {
	Resume(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
}

type snapshotCapable interface {
	Snapshot(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
}

type restoreCapable interface {
	Restore(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
}

type inspectCapable interface {
	Inspect(context.Context, *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error)
}

type lifecycleAdapter struct {
	base machinev1alpha1.MachineService
}

// Adapt wraps a MachineService and exposes a strict lifecycle interface.
// Drivers can optionally implement Resume/Snapshot/Restore/Inspect directly.
func Adapt(service machinev1alpha1.MachineService) MachineLifecycle {
	return &lifecycleAdapter{base: service}
}

func (adapter *lifecycleAdapter) Create(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return adapter.base.Create(ctx, machine)
}

func (adapter *lifecycleAdapter) Start(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return adapter.base.Start(ctx, machine)
}

func (adapter *lifecycleAdapter) Pause(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return adapter.base.Pause(ctx, machine)
}

func (adapter *lifecycleAdapter) Resume(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	if impl, ok := adapter.base.(resumeCapable); ok {
		return impl.Resume(ctx, machine)
	}
	return nil, fmt.Errorf("%w: resume", ErrUnsupported)
}

func (adapter *lifecycleAdapter) Snapshot(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	if impl, ok := adapter.base.(snapshotCapable); ok {
		return impl.Snapshot(ctx, machine)
	}
	return nil, fmt.Errorf("%w: snapshot", ErrUnsupported)
}

func (adapter *lifecycleAdapter) Restore(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	if impl, ok := adapter.base.(restoreCapable); ok {
		return impl.Restore(ctx, machine)
	}
	return nil, fmt.Errorf("%w: restore", ErrUnsupported)
}

func (adapter *lifecycleAdapter) Stop(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return adapter.base.Stop(ctx, machine)
}

func (adapter *lifecycleAdapter) Destroy(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return adapter.base.Delete(ctx, machine)
}

func (adapter *lifecycleAdapter) Inspect(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	if impl, ok := adapter.base.(inspectCapable); ok {
		return impl.Inspect(ctx, machine)
	}
	return adapter.base.Get(ctx, machine)
}

