// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"strings"
	"time"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/log"
)

const (
	workloadReconcileInterval = 20 * time.Second
	workloadRecoverRetryAfter = 30 * time.Second
)

func (server *Server) reconcileWorkloads(ctx context.Context) {
	server.reconcileWorkloadsOnce(ctx)

	ticker := time.NewTicker(workloadReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.reconcileWorkloadsOnce(ctx)
		}
	}
}

func (server *Server) reconcileWorkloadsOnce(ctx context.Context) {
	records, err := server.workloads.List()
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not list workload records for reconcile")
		return
	}
	if len(records) == 0 {
		return
	}

	machines, err := server.aggregateMachines(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not aggregate machines for reconcile")
		return
	}

	states := map[string]machineapi.MachineState{}
	for _, machine := range machines {
		states[machine.Name] = machine.State
		states[machine.ID] = machine.State
	}

	for _, record := range records {
		machineName := strings.TrimSpace(record.Machine)
		if machineName == "" {
			continue
		}

		if state, ok := states[machineName]; ok {
			switch state {
			case machineapi.MachineStateRunning, machineapi.MachineStateCreated, machineapi.MachineStateExited, machineapi.MachineStateRestarting, machineapi.MachineStatePaused, machineapi.MachineStateSuspended:
				server.markWorkloadRecoverSuccess(machineName)
				continue
			}
		}

		if !server.shouldAttemptWorkloadRecovery(machineName) {
			continue
		}

		request := record.Request
		request.Name = machineName
		if strings.TrimSpace(request.NodeName) == "" && strings.TrimSpace(record.Node) != "" {
			request.NodeName = strings.TrimSpace(record.Node)
		}

		_, recoverErr := server.deploySingle(controlplaneapi.WithServerMode(ctx), &request, machineName, map[string]struct{}{})
		if recoverErr != nil {
			log.G(ctx).WithError(recoverErr).WithField("machine", machineName).Warn("workload auto-reconcile failed")
			continue
		}

		server.markWorkloadRecoverSuccess(machineName)
		log.G(ctx).WithField("machine", machineName).Info("workload auto-reconciled")
	}
}

func (server *Server) shouldAttemptWorkloadRecovery(machineName string) bool {
	server.recoverMu.Lock()
	defer server.recoverMu.Unlock()

	now := time.Now().UTC()
	if last, ok := server.recoverAt[machineName]; ok {
		if now.Sub(last) < workloadRecoverRetryAfter {
			return false
		}
	}

	server.recoverAt[machineName] = now
	return true
}

func (server *Server) markWorkloadRecoverSuccess(machineName string) {
	server.recoverMu.Lock()
	delete(server.recoverAt, machineName)
	server.recoverMu.Unlock()
}
