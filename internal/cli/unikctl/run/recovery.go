// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package run

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/localdeploy"
	"unikctl.sh/log"
)

func (opts *RunOptions) persistLocalDeployment(ctx context.Context, machine *machineapi.Machine, args []string) {
	if controlplaneapi.InServerMode(ctx) {
		return
	}
	if machine == nil {
		return
	}

	machineName := strings.TrimSpace(machine.Name)
	if machineName == "" {
		return
	}

	store, err := localdeploy.NewStore(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not open local deploy store")
		return
	}

	memory := strings.TrimSpace(opts.Memory)
	if memory == "" {
		if qty := machine.Spec.Resources.Requests.Memory(); qty != nil {
			qtyText := strings.TrimSpace(qty.String())
			if qtyText != "" && qtyText != "0" {
				memory = qtyText
			}
		}
	}

	spec := localdeploy.RecoverSpec{
		Args:         normalizeRecoverArgs(args),
		Debug:        opts.Debug || opts.WithKernelDbg,
		Memory:       memory,
		Name:         machineName,
		Rootfs:       strings.TrimSpace(opts.Rootfs),
		Runtime:      strings.TrimSpace(opts.Runtime),
		Target:       strings.TrimSpace(opts.Target),
		Platform:     strings.TrimSpace(opts.Platform),
		Architecture: strings.TrimSpace(opts.Architecture),
		Ports:        append([]string{}, opts.Ports...),
	}

	if err := store.Upsert(machineName, spec); err != nil {
		log.G(ctx).WithError(err).WithField("machine", machineName).Debug("could not persist local deployment recovery spec")
	}
}

func normalizeRecoverArgs(args []string) []string {
	resolved := append([]string{}, args...)
	if len(resolved) == 0 {
		return resolved
	}

	first := strings.TrimSpace(resolved[0])
	if first == "" || filepath.IsAbs(first) {
		return resolved
	}

	if _, err := os.Stat(first); err != nil {
		return resolved
	}

	abs, err := filepath.Abs(first)
	if err != nil {
		return resolved
	}

	resolved[0] = abs
	return resolved
}
