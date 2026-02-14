// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"strings"

	machineapi "unikctl.sh/api/machine/v1alpha1"
)

func parseMachineState(value string) machineapi.MachineState {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(machineapi.MachineStateCreated):
		return machineapi.MachineStateCreated
	case string(machineapi.MachineStateFailed):
		return machineapi.MachineStateFailed
	case string(machineapi.MachineStateRestarting):
		return machineapi.MachineStateRestarting
	case string(machineapi.MachineStateRunning):
		return machineapi.MachineStateRunning
	case string(machineapi.MachineStatePaused):
		return machineapi.MachineStatePaused
	case string(machineapi.MachineStateSuspended):
		return machineapi.MachineStateSuspended
	case string(machineapi.MachineStateExited):
		return machineapi.MachineStateExited
	case string(machineapi.MachineStateErrored):
		return machineapi.MachineStateErrored
	default:
		return machineapi.MachineStateUnknown
	}
}
