// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package platform

import (
	"context"
	"fmt"
	"sort"

	zip "api.zip"
	"github.com/acorn-io/baaah/pkg/merr"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
)

type machineV1alpha1ServiceIterator struct {
	order      []Platform
	strategies map[Platform]machinev1alpha1.MachineService
}

// NewMachineV1alpha1ServiceIterator returns a
// machinev1alpha1.MachineService-compatible implementation which iterates over
// each supported host platform and calls the representing method.  This is
// useful in circumstances where the platform is not supplied.  The first
// platform strategy to succeed is returned in all circumstances.
func NewMachineV1alpha1ServiceIterator(ctx context.Context) (machinev1alpha1.MachineService, error) {
	var err error
	iterator := machineV1alpha1ServiceIterator{
		order:      []Platform{},
		strategies: map[Platform]machinev1alpha1.MachineService{},
	}

	for platform, strategy := range hostSupportedStrategies() {
		iterator.strategies[platform], err = strategy.NewMachineV1alpha1(ctx)
		if err != nil {
			return nil, err
		}
	}

	iterator.order = preferredPlatformOrder(iterator.strategies)

	return &iterator, nil
}

func preferredPlatformOrder(strategies map[Platform]machinev1alpha1.MachineService) []Platform {
	order := make([]Platform, 0, len(strategies))
	appendIfPresent := func(platform Platform) {
		if _, ok := strategies[platform]; ok {
			order = append(order, platform)
		}
	}

	appendIfPresent(PlatformFirecracker)
	appendIfPresent(PlatformQEMU)
	appendIfPresent(PlatformXen)

	remaining := make([]string, 0, len(strategies))
	known := map[Platform]struct{}{}
	for _, platform := range order {
		known[platform] = struct{}{}
	}
	for platform := range strategies {
		if _, ok := known[platform]; ok {
			continue
		}
		remaining = append(remaining, platform.String())
	}
	sort.Strings(remaining)
	for _, name := range remaining {
		order = append(order, Platform(name))
	}

	return order
}

// Create implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Create(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Create(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Start implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Start(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Start(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Pause implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Pause(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Pause(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Stop implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Stop(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Stop(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Update implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Update(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Update(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Delete implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Delete(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Delete(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Get implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Get(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.Get(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return ret, nil
	}

	return machine, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// List implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) List(ctx context.Context, cached *machinev1alpha1.MachineList) (*machinev1alpha1.MachineList, error) {
	found := []zip.Object[machinev1alpha1.MachineSpec, machinev1alpha1.MachineStatus]{}

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		ret, err := strategy.List(ctx, &machinev1alpha1.MachineList{})
		if err != nil {
			continue
		}

		found = append(found, ret.Items...)
	}

	cached.Items = found

	return cached, nil
}

// Watch implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Watch(ctx context.Context, machine *machinev1alpha1.Machine) (chan *machinev1alpha1.Machine, chan error, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		eventChan, errChan, err := strategy.Watch(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return eventChan, errChan, nil
	}

	return nil, nil, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}

// Logs implements unikctl.sh/api/machine/v1alpha1.MachineService
func (iterator *machineV1alpha1ServiceIterator) Logs(ctx context.Context, machine *machinev1alpha1.Machine) (chan string, chan error, error) {
	var errs []error

	for _, platform := range iterator.order {
		strategy := iterator.strategies[platform]
		logChan, errChan, err := strategy.Logs(ctx, machine)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return logChan, errChan, nil
	}

	return nil, nil, fmt.Errorf("all iterated platforms failed: %w", merr.NewErrors(errs...))
}
