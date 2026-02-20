// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"math"
	"strings"
	"time"

	gocpu "github.com/shirou/gopsutil/v3/cpu"
	goprocess "github.com/shirou/gopsutil/v3/process"

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
	machineIndex := map[string]machineStatus{}
	for _, machine := range machines {
		states[machine.Name] = machine.State
		states[machine.ID] = machine.State
		machineIndex[machine.Name] = machine
	}

	nodePressure := map[string]float64{}
	if server.nodes != nil {
		if nodes, err := server.nodes.List(); err == nil {
			for _, node := range nodes {
				if node.CapacityMemBytes <= 0 {
					continue
				}
				pressure := float64(node.UsedMemBytes) / float64(node.CapacityMemBytes)
				if pressure < 0 {
					pressure = 0
				}
				if pressure > 1 {
					pressure = 1
				}
				nodePressure[node.Name] = pressure
			}
		}
	}
	if _, ok := nodePressure[hostname()]; !ok {
		nodePressure[hostname()] = 0
	}

	localRunning := []string{}
	for _, record := range records {
		machineName := strings.TrimSpace(record.Machine)
		if machineName == "" {
			continue
		}

		state, ok := states[machineName]
		if !ok {
			continue
		}

		if state != machineapi.MachineStateRunning &&
			state != machineapi.MachineStateCreated &&
			state != machineapi.MachineStateExited &&
			state != machineapi.MachineStateRestarting &&
			state != machineapi.MachineStatePaused &&
			state != machineapi.MachineStateSuspended {
			continue
		}

		if machine, present := machineIndex[machineName]; !present || (strings.TrimSpace(machine.Node) != "" && strings.TrimSpace(machine.Node) != hostname()) {
			continue
		}

		localRunning = append(localRunning, machineName)
	}

	stealDeltaMillis := server.sampleHostStealDeltaMillis()
	stealShareMillis := int64(0)
	if len(localRunning) > 0 && stealDeltaMillis > 0 {
		stealShareMillis = stealDeltaMillis / int64(len(localRunning))
	}
	localRunningSet := map[string]struct{}{}
	for _, machineName := range localRunning {
		localRunningSet[machineName] = struct{}{}
	}

	for _, record := range records {
		machineName := strings.TrimSpace(record.Machine)
		if machineName == "" {
			continue
		}

		if state, ok := states[machineName]; ok {
			switch state {
			case machineapi.MachineStateRunning, machineapi.MachineStateCreated, machineapi.MachineStateExited, machineapi.MachineStateRestarting, machineapi.MachineStatePaused, machineapi.MachineStateSuspended:
				if machine, present := machineIndex[machineName]; present {
					actualRSS := int64(0)
					if strings.TrimSpace(machine.Node) == "" || strings.TrimSpace(machine.Node) == hostname() {
						if machine.Pid > 0 {
							if process, err := goprocess.NewProcess(machine.Pid); err == nil {
								if mem, err := process.MemoryInfo(); err == nil {
									actualRSS = int64(mem.RSS)
								}
							}
						}
					}

					pressure := nodePressure[firstNonEmpty(strings.TrimSpace(record.Node), hostname())]
					stealMillis := record.StealTimeMillis
					if _, local := localRunningSet[machineName]; local && stealShareMillis > 0 {
						stealMillis += stealShareMillis
					}

					if err := server.workloads.UpdateRuntimeStats(machineName, actualRSS, stealMillis, pressure); err != nil {
						log.G(ctx).WithError(err).WithField("machine", machineName).Debug("could not update workload runtime stats")
					}
				}

				server.markWorkloadRecoverSuccess(machineName)
				continue
			}
		}

		if !server.shouldAttemptWorkloadRecovery(machineName) {
			continue
		}

		if err := server.workloads.IncrementRestart(machineName); err != nil {
			log.G(ctx).WithError(err).WithField("machine", machineName).Debug("could not increment workload restart counter")
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

func (server *Server) sampleHostStealDeltaMillis() int64 {
	current, err := hostStealMillis()
	if err != nil || current < 0 {
		return 0
	}

	server.hostStealMu.Lock()
	defer server.hostStealMu.Unlock()

	if !server.hostStealInitialized {
		server.hostStealInitialized = true
		server.hostStealLastMillis = current
		return 0
	}

	delta := current - server.hostStealLastMillis
	server.hostStealLastMillis = current
	if delta < 0 {
		return 0
	}

	return delta
}

func hostStealMillis() (int64, error) {
	times, err := gocpu.Times(false)
	if err != nil {
		return 0, err
	}
	if len(times) == 0 {
		return 0, nil
	}

	return int64(math.Round(times[0].Steal * 1000)), nil
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
