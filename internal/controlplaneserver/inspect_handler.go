// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"net/http"
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"unikctl.sh/internal/controlplaneapi"
)

func (server *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodGet {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "status"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	target := strings.TrimPrefix(strings.TrimSpace(r.URL.Path), "/v1/inspect/")
	if decoded, err := url.PathUnescape(target); err == nil {
		target = decoded
	}
	target = strings.TrimSpace(target)
	if target == "" {
		writeErrorTrace(w, http.StatusBadRequest, "inspect target is required", traceID)
		return
	}
	tenantScope, scopedTenant := tenantScopeFromRequest(r)

	machines, err := server.aggregateMachines(r.Context())
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, err.Error(), traceID)
		return
	}

	selected := machineStatus{}
	found := false
	for _, machine := range machines {
		if machine.Name == target || machine.ID == target {
			selected = machine
			found = true
			break
		}
	}
	if !found {
		writeErrorTrace(w, http.StatusNotFound, "deployment not found", traceID)
		return
	}
	if scopedTenant {
		if err := server.ensureTenantMachineAccess(selected.Name, tenantScope); err != nil {
			writeErrorTrace(w, http.StatusNotFound, "deployment not found", traceID)
			return
		}
	}

	response := controlplaneapi.InspectResponse{
		ID:           selected.ID,
		Name:         selected.Name,
		Node:         selected.Node,
		State:        string(selected.State),
		Driver:       selected.Plat,
		Architecture: selected.Arch,
		Kernel:       selected.Kernel,
		Args:         selected.Args,
		CreatedAt:    selected.CreatedAt,
		Ports:        selected.Ports,
	}

	workload, workloadFound, err := server.workloads.Get(selected.Name)
	if err == nil && workloadFound {
		response.CPURequest = firstNonEmpty(
			strings.TrimSpace(workload.Request.CPU),
			formatCPUMilli(workload.RequestedCPUMilli),
		)
		response.MemoryRequest = firstNonEmpty(
			strings.TrimSpace(workload.Request.Memory),
			formatBytes(workload.RequestedMemBytes),
		)
	}

	if server.warmPool != nil {
		if warm, ok, err := server.warmPool.GetByMachine(selected.Name); err == nil && ok {
			response.SnapshotPath = strings.TrimSpace(warm.SnapshotPath)
			response.SnapshotMem = strings.TrimSpace(warm.SnapshotMem)
			response.SnapshotMeta = strings.TrimSpace(warm.SnapshotMeta)
			response.SnapshotState = firstNonEmpty(strings.TrimSpace(warm.State), "unknown")
		}
	}
	if strings.TrimSpace(response.SnapshotState) == "" {
		response.SnapshotState = "none"
	}

	writeJSON(w, http.StatusOK, response)
}

func formatCPUMilli(value int64) string {
	if value <= 0 {
		return ""
	}
	quantity := resource.NewMilliQuantity(value, resource.DecimalSI)
	return quantity.String()
}

func formatBytes(value int64) string {
	if value <= 0 {
		return ""
	}
	quantity := resource.NewQuantity(value, resource.BinarySI)
	return quantity.String()
}
