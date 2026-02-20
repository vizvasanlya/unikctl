// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"fmt"
	"math"
	"net/http"
	"sort"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/internal/controlplaneapi"
	mplatform "unikctl.sh/machine/platform"
)

func (server *Server) handleSubstrateStatus(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)
	if r.Method != http.MethodGet {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "status"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	tenantScope, scopedTenant := tenantScopeFromRequest(r)
	tenantMachines := map[string]struct{}{}
	tenantNodes := map[string]struct{}{}
	if scopedTenant {
		set, err := server.tenantMachineSet(tenantScope)
		if err != nil {
			writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing tenant workloads: %v", err), traceID)
			return
		}
		tenantMachines = set

		nodes, err := server.tenantNodeSet(tenantScope)
		if err != nil {
			writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing tenant nodes: %v", err), traceID)
			return
		}
		tenantNodes = nodes
	}

	nodes, err := server.nodes.List()
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing nodes: %v", err), traceID)
		return
	}
	filteredNodes := make([]nodeRecord, 0, len(nodes))
	for _, node := range nodes {
		if scopedTenant {
			if _, ok := tenantNodes[node.Name]; !ok {
				continue
			}
		}
		filteredNodes = append(filteredNodes, node)
	}

	machines, err := server.aggregateMachines(r.Context())
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing machines: %v", err), traceID)
		return
	}
	runningMachines := int64(0)
	for _, machine := range machines {
		if machine.State != machineapi.MachineStateRunning {
			continue
		}
		if scopedTenant {
			if _, ok := tenantMachines[machine.Name]; !ok {
				continue
			}
		}
		runningMachines++
	}

	workloads, err := server.workloads.List()
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, fmt.Sprintf("listing workloads: %v", err), traceID)
		return
	}

	type aggregate struct {
		instances    int64
		cpuMilli     int64
		memoryBytes  int64
		actualRSS    int64
		hostOverhead int64
	}

	tenantAgg := map[string]aggregate{}
	totalRequestedMem := int64(0)
	totalRequestedCPU := int64(0)
	totalOverhead := int64(0)
	workloadCount := int64(0)

	for _, workload := range workloads {
		tenant := normalizeTenant(workload.Tenant)
		if scopedTenant && tenant != tenantScope {
			continue
		}

		acc := tenantAgg[tenant]
		acc.instances++
		acc.cpuMilli += maxInt64(workload.RequestedCPUMilli, 0)
		acc.memoryBytes += maxInt64(workload.RequestedMemBytes, 0)
		acc.actualRSS += maxInt64(workload.ActualRSSBytes, 0)
		acc.hostOverhead += maxInt64(workload.HostOverheadBytes, 0)
		tenantAgg[tenant] = acc

		totalRequestedCPU += maxInt64(workload.RequestedCPUMilli, 0)
		totalRequestedMem += maxInt64(workload.RequestedMemBytes, 0)
		totalOverhead += maxInt64(workload.HostOverheadBytes, 0)
		workloadCount++
	}

	tenantRows := make([]controlplaneapi.TenantUtilization, 0, len(tenantAgg))
	for tenant, acc := range tenantAgg {
		tenantRows = append(tenantRows, controlplaneapi.TenantUtilization{
			Tenant:       tenant,
			Instances:    acc.instances,
			CPUMilli:     acc.cpuMilli,
			MemoryBytes:  acc.memoryBytes,
			ActualRSS:    acc.actualRSS,
			HostOverhead: acc.hostOverhead,
		})
	}
	sort.SliceStable(tenantRows, func(i, j int) bool {
		return tenantRows[i].Tenant < tenantRows[j].Tenant
	})

	readyNodes := int64(0)
	totalCapacityCPU := int64(0)
	totalCapacityMem := int64(0)
	for _, node := range filteredNodes {
		if node.State == nodeStateReady {
			readyNodes++
		}
		totalCapacityCPU += maxInt64(node.CapacityCPUMilli, 0)
		totalCapacityMem += maxInt64(node.CapacityMemBytes, 0)
	}
	if totalCapacityCPU <= 0 {
		totalCapacityCPU = 1
	}
	if totalCapacityMem <= 0 {
		totalCapacityMem = 1
	}

	safetyMarginPct := parseIntEnv("UNIKCTL_DENSITY_SAFETY_MARGIN_PCT", 15)
	if safetyMarginPct < 0 {
		safetyMarginPct = 0
	}
	if safetyMarginPct > 90 {
		safetyMarginPct = 90
	}

	effectiveMemCap := int64(float64(totalCapacityMem) * (float64(100-safetyMarginPct) / 100.0))
	effectiveCPUCap := int64(float64(totalCapacityCPU) * (float64(100-safetyMarginPct) / 100.0))
	if effectiveMemCap <= 0 {
		effectiveMemCap = totalCapacityMem
	}
	if effectiveCPUCap <= 0 {
		effectiveCPUCap = totalCapacityCPU
	}

	theoreticalDensity := float64(0)
	if workloadCount > 0 {
		avgMem := maxInt64(totalRequestedMem/workloadCount, 1)
		avgCPU := maxInt64(totalRequestedCPU/workloadCount, 1)
		avgOverhead := maxInt64(totalOverhead/workloadCount, 0)

		memBound := float64(effectiveMemCap) / float64(maxInt64(avgMem+avgOverhead, 1))
		cpuBound := float64(effectiveCPUCap) / float64(maxInt64(avgCPU, 1))
		theoreticalDensity = math.Floor(math.Min(memBound, cpuBound))
		if theoreticalDensity < 0 {
			theoreticalDensity = 0
		}
	}

	observedDensity := float64(runningMachines)
	if readyNodes > 0 {
		observedDensity = float64(runningMachines) / float64(readyNodes)
	}

	driverOverheads, err := server.workloads.DriverOverheadAverages()
	if err != nil {
		driverOverheads = map[string]int64{}
	}

	driverDefault := "unknown"
	if platform, _, detectErr := mplatform.Detect(r.Context()); detectErr == nil {
		switch platform {
		case mplatform.PlatformFirecracker:
			driverDefault = "firecracker"
		case mplatform.PlatformQEMU:
			driverDefault = "qemu"
		default:
			driverDefault = platform.String()
		}
	}

	response := controlplaneapi.SubstrateStatusResponse{
		DriverDefault:          driverDefault,
		SnapshotFastPath:       server.snapshotFastPath,
		WarmPoolSize:           func() int { if server.warmPool == nil { return 0 }; return server.warmPool.TargetSize() }(),
		AverageColdBootMillis:  server.metrics.AverageDeployLatencyMillis(),
		AverageResumeMillis:    server.metrics.AverageWarmResumeLatencyMillis(),
		ObservedDensity:        observedDensity,
		TheoreticalDensity:     theoreticalDensity,
		PerTenantUtilization:   tenantRows,
		DriverOverheadAverages: driverOverheads,
	}

	writeJSON(w, http.StatusOK, response)
}
