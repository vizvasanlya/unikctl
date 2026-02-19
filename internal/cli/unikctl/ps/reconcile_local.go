// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package ps

import (
	"context"
	"errors"
	"strings"
	"time"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/internal/cli/unikctl/run"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/localdeploy"
	"unikctl.sh/log"
)

const localRecoverRetryAfter = 30 * time.Second

var errMissingRecoverArgs = errors.New("missing recovery args for deployment")

func (opts *PsOptions) reconcileLocalDeployments(ctx context.Context, controller machineapi.MachineService) {
	if controller == nil || controlplaneapi.Enabled(ctx) || controlplaneapi.InServerMode(ctx) {
		return
	}

	store, err := localdeploy.NewStore(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not open local deploy store")
		return
	}

	records, err := store.List()
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not list local deploy records")
		return
	}
	if len(records) == 0 {
		return
	}

	machineList, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not list machines for local reconcile")
		return
	}

	states := map[string]machineapi.MachineState{}
	for _, machine := range machineList.Items {
		states[machine.Name] = machine.Status.State
		states[string(machine.UID)] = machine.Status.State
	}

	for _, record := range records {
		machineName := strings.TrimSpace(record.Machine)
		if machineName == "" {
			continue
		}

		if state, ok := states[machineName]; ok {
			switch state {
			case machineapi.MachineStateRunning, machineapi.MachineStateCreated, machineapi.MachineStateExited, machineapi.MachineStateRestarting, machineapi.MachineStatePaused, machineapi.MachineStateSuspended:
				_ = store.MarkRecoverResult(machineName, nil)
				continue
			}
		}

		if !record.LastRecoverAttempt.IsZero() && time.Since(record.LastRecoverAttempt) < localRecoverRetryAfter {
			continue
		}

		spec := record.Spec
		if len(spec.Args) == 0 {
			_ = store.MarkRecoverResult(machineName, errMissingRecoverArgs)
			continue
		}

		recoverOpts := &run.RunOptions{
			Detach:       true,
			Debug:        spec.Debug,
			Memory:       firstNonEmpty(strings.TrimSpace(spec.Memory), "64Mi"),
			Name:         machineName,
			Rootfs:       strings.TrimSpace(spec.Rootfs),
			Runtime:      strings.TrimSpace(spec.Runtime),
			Target:       strings.TrimSpace(spec.Target),
			Platform:     strings.TrimSpace(spec.Platform),
			Architecture: strings.TrimSpace(spec.Architecture),
			Ports:        append([]string{}, spec.Ports...),
		}

		recoverCtx := controlplaneapi.WithServerMode(ctx)
		recoverErr := run.Run(recoverCtx, recoverOpts, append([]string{}, spec.Args...)...)
		_ = store.MarkRecoverResult(machineName, recoverErr)
		if recoverErr != nil {
			log.G(ctx).WithError(recoverErr).WithField("machine", machineName).Warn("auto-reconcile failed")
			continue
		}

		log.G(ctx).WithField("machine", machineName).Info("auto-reconciled missing machine")
	}
}
