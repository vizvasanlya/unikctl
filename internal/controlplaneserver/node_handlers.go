// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"unikctl.sh/internal/controlplaneapi"
)

func (server *Server) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "node"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	request := controlplaneapi.NodeRegisterRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErrorTrace(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err), traceID)
		return
	}

	if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.AgentURL) == "" {
		writeErrorTrace(w, http.StatusBadRequest, "node register requires name and agent_url", traceID)
		return
	}

	node, err := server.nodes.Register(request)
	if err != nil {
		writeErrorTrace(w, http.StatusInternalServerError, err.Error(), traceID)
		return
	}

	writeJSON(w, http.StatusOK, controlplaneapi.NodeActionResponse{
		Name:    node.Name,
		State:   string(node.State),
		Message: "registered",
	})
}

func (server *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "node"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	request := controlplaneapi.NodeHeartbeatRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErrorTrace(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err), traceID)
		return
	}

	if strings.TrimSpace(request.Name) == "" {
		writeErrorTrace(w, http.StatusBadRequest, "node heartbeat requires name", traceID)
		return
	}

	node, err := server.nodes.Heartbeat(request)
	if err != nil {
		writeErrorTrace(w, http.StatusNotFound, err.Error(), traceID)
		return
	}

	writeJSON(w, http.StatusOK, controlplaneapi.NodeActionResponse{
		Name:    node.Name,
		State:   string(node.State),
		Message: "heartbeat accepted",
	})
}

func (server *Server) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)

	if r.Method != http.MethodPost {
		writeErrorTrace(w, http.StatusMethodNotAllowed, "method not allowed", traceID)
		return
	}

	if status, err := server.authorize(r, "status"); err != nil {
		writeErrorTrace(w, status, err.Error(), traceID)
		return
	}

	rest := strings.TrimPrefix(strings.TrimSpace(r.URL.Path), "/v1/nodes/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeErrorTrace(w, http.StatusNotFound, "invalid node action path", traceID)
		return
	}

	nodeName := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	if nodeName == "" || action == "" {
		writeErrorTrace(w, http.StatusBadRequest, "node name and action are required", traceID)
		return
	}

	switch action {
	case "cordon":
		node, err := server.nodes.SetCordon(nodeName, true)
		if err != nil {
			writeErrorTrace(w, http.StatusNotFound, err.Error(), traceID)
			return
		}
		writeJSON(w, http.StatusOK, controlplaneapi.NodeActionResponse{
			Name:    node.Name,
			State:   string(node.State),
			Message: "node cordoned",
		})

	case "uncordon":
		node, err := server.nodes.SetCordon(nodeName, false)
		if err != nil {
			writeErrorTrace(w, http.StatusNotFound, err.Error(), traceID)
			return
		}
		writeJSON(w, http.StatusOK, controlplaneapi.NodeActionResponse{
			Name:    node.Name,
			State:   string(node.State),
			Message: "node uncordoned",
		})

	case "drain":
		if _, err := server.nodes.SetDraining(nodeName, true); err != nil {
			writeErrorTrace(w, http.StatusNotFound, err.Error(), traceID)
			return
		}

		migrated, failed, err := server.rescheduleDrainedNode(r.Context(), nodeName)
		if err != nil {
			_, _ = server.nodes.SetDraining(nodeName, false)
			_, _ = server.nodes.SetCordon(nodeName, true)
			writeErrorTrace(w, http.StatusConflict, err.Error(), traceID)
			return
		}

		node, err := server.nodes.SetDraining(nodeName, false)
		if err != nil {
			writeErrorTrace(w, http.StatusInternalServerError, err.Error(), traceID)
			return
		}
		if _, err := server.nodes.SetCordon(nodeName, true); err != nil {
			writeErrorTrace(w, http.StatusInternalServerError, err.Error(), traceID)
			return
		}

		writeJSON(w, http.StatusOK, controlplaneapi.NodeActionResponse{
			Name:     node.Name,
			State:    string(node.State),
			Message:  "node drained",
			Migrated: migrated,
			Failed:   failed,
		})

	default:
		writeErrorTrace(w, http.StatusNotFound, "unknown node action", traceID)
	}
}

func (server *Server) rescheduleDrainedNode(ctx context.Context, nodeName string) (int, int, error) {
	workloads, err := server.workloads.ByNode(nodeName)
	if err != nil {
		return 0, 0, err
	}

	if len(workloads) == 0 {
		return 0, 0, nil
	}

	sourceNode, ok, err := server.nodes.Get(nodeName)
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, fmt.Errorf("drain source node not found: %s", nodeName)
	}

	exclude := map[string]struct{}{
		nodeName: {},
	}

	migrated := 0
	failed := 0
	failures := []string{}

	for _, workload := range workloads {
		request := workload.Request
		request.Name = workload.Machine
		request.NodeName = ""
		request.NodeSelector = nil

		targetNode, err := server.selectNodeForDeploy(&request, exclude)
		if err != nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: %v", workload.Machine, err))
			continue
		}
		if targetNode == nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: no schedulable target node", workload.Machine))
			continue
		}

		if err := server.deployToNode(ctx, *targetNode, &request); err != nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: deploy to %s failed: %v", workload.Machine, targetNode.Name, err))
			continue
		}

		if err := server.destroyOnNode(ctx, sourceNode, &controlplaneapi.DestroyRequest{
			Names: []string{workload.Machine},
		}); err != nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: destroy on %s failed: %v", workload.Machine, sourceNode.Name, err))
			continue
		}

		if err := server.workloads.Upsert(workload.Machine, targetNode.Name, request); err != nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: workload update failed: %v", workload.Machine, err))
			continue
		}

		migrated++
	}

	if failed > 0 {
		return migrated, failed, fmt.Errorf("drain completed with failures: %s", strings.Join(failures, "; "))
	}

	return migrated, failed, nil
}

func (server *Server) reconcileNodes(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = server.nodes.MarkOfflineStale(nodeHeartbeatStaleAfter)
		}
	}
}

func nodeRecordToAPI(record nodeRecord) controlplaneapi.Node {
	return controlplaneapi.Node{
		Name:             record.Name,
		Address:          record.Address,
		AgentURL:         record.AgentURL,
		State:            string(record.State),
		Cordoned:         record.Cordoned,
		Draining:         record.Draining,
		Labels:           cloneLabels(record.Labels),
		CapacityCPUMilli: record.CapacityCPUMilli,
		CapacityMemBytes: record.CapacityMemBytes,
		UsedCPUMilli:     record.UsedCPUMilli,
		UsedMemBytes:     record.UsedMemBytes,
		Machines:         record.Machines,
		UpdatedAt:        record.UpdatedAt,
	}
}
