// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"testing"

	"unikctl.sh/internal/controlplaneapi"
)

func TestSelectEligibleNode_StrictAdmissionRejectsOverCapacity(t *testing.T) {
	nodes := []nodeRecord{
		{
			Name:             "node-a",
			State:            nodeStateReady,
			AgentURL:         "http://127.0.0.1:7780",
			CapacityCPUMilli: 1000,
			UsedCPUMilli:     900,
			CapacityMemBytes: 256 * 1024 * 1024,
			UsedMemBytes:     220 * 1024 * 1024,
			Labels:           map[string]string{"tenant": "default"},
		},
	}

	request := &controlplaneapi.DeployRequest{
		CPU:    "1500m",
		Memory: "512Mi",
	}

	_, err := selectEligibleNode(nodes, request, nil, nil)
	if err == nil {
		t.Fatalf("expected admission rejection for over-capacity request")
	}

	status, code, _, ok := apiErrorParts(err)
	if !ok {
		t.Fatalf("expected structured api error, got: %v", err)
	}
	if status != 409 {
		t.Fatalf("unexpected status: got=%d want=%d", status, 409)
	}
	if code != "admission_rejected_capacity" {
		t.Fatalf("unexpected code: got=%q", code)
	}
}

func TestSelectEligibleNode_DoesNotMutateRequestResources(t *testing.T) {
	nodes := []nodeRecord{
		{
			Name:             "node-a",
			State:            nodeStateReady,
			AgentURL:         "http://127.0.0.1:7780",
			CapacityCPUMilli: 4000,
			UsedCPUMilli:     0,
			CapacityMemBytes: 4 * 1024 * 1024 * 1024,
			UsedMemBytes:     0,
			Labels:           map[string]string{"tenant": "default"},
		},
	}

	request := &controlplaneapi.DeployRequest{
		CPU:    "2500m",
		Memory: "512Mi",
	}

	_, err := selectEligibleNode(nodes, request, nil, map[string]int{})
	if err != nil {
		t.Fatalf("unexpected scheduling error: %v", err)
	}

	if request.CPU != "2500m" {
		t.Fatalf("cpu request mutated: got=%q want=%q", request.CPU, "2500m")
	}
	if request.Memory != "512Mi" {
		t.Fatalf("memory request mutated: got=%q want=%q", request.Memory, "512Mi")
	}
}

func TestSelectEligibleNode_RespectsSchedulerStrategies(t *testing.T) {
	nodes := []nodeRecord{
		{
			Name:             "node-a",
			State:            nodeStateReady,
			AgentURL:         "http://127.0.0.1:7780",
			CapacityCPUMilli: 8000,
			UsedCPUMilli:     1000,
			CapacityMemBytes: 16 * 1024 * 1024 * 1024,
			UsedMemBytes:     1 * 1024 * 1024 * 1024,
			Labels:           map[string]string{"tenant": "default"},
		},
		{
			Name:             "node-b",
			State:            nodeStateReady,
			AgentURL:         "http://127.0.0.1:7780",
			CapacityCPUMilli: 4000,
			UsedCPUMilli:     3500,
			CapacityMemBytes: 8 * 1024 * 1024 * 1024,
			UsedMemBytes:     7 * 1024 * 1024 * 1024,
			Labels:           map[string]string{"tenant": "default"},
		},
	}

	request := &controlplaneapi.DeployRequest{CPU: "500m", Memory: "64Mi"}

	t.Setenv("UNIKCTL_SCHEDULER_STRATEGY", string(schedulerStrategySpread))
	spreadNode, err := selectEligibleNode(nodes, request, nil, nil)
	if err != nil {
		t.Fatalf("spread scheduling failed: %v", err)
	}
	if spreadNode.Name != "node-a" {
		t.Fatalf("spread strategy should pick most-free node, got=%s", spreadNode.Name)
	}

	t.Setenv("UNIKCTL_SCHEDULER_STRATEGY", string(schedulerStrategyBinpack))
	binpackNode, err := selectEligibleNode(nodes, request, nil, nil)
	if err != nil {
		t.Fatalf("binpack scheduling failed: %v", err)
	}
	if binpackNode.Name != "node-b" {
		t.Fatalf("binpack strategy should pick tightest-fit node, got=%s", binpackNode.Name)
	}

}

func TestSelectEligibleNode_RejectsInvalidResourceRequests(t *testing.T) {
	nodes := []nodeRecord{
		{
			Name:             "node-a",
			State:            nodeStateReady,
			AgentURL:         "http://127.0.0.1:7780",
			CapacityCPUMilli: 4000,
			UsedCPUMilli:     0,
			CapacityMemBytes: 4 * 1024 * 1024 * 1024,
			UsedMemBytes:     0,
			Labels:           map[string]string{"tenant": "default"},
		},
	}

	_, err := selectEligibleNode(nodes, &controlplaneapi.DeployRequest{
		CPU:    "0",
		Memory: "128Mi",
	}, nil, nil)
	if err == nil {
		t.Fatalf("expected invalid CPU request to be rejected")
	}

	status, code, _, ok := apiErrorParts(err)
	if !ok {
		t.Fatalf("expected structured api error, got: %v", err)
	}
	if status != 400 {
		t.Fatalf("unexpected status: got=%d want=%d", status, 400)
	}
	if code != "invalid_cpu_request" {
		t.Fatalf("unexpected code: got=%q want=%q", code, "invalid_cpu_request")
	}

	_, err = selectEligibleNode(nodes, &controlplaneapi.DeployRequest{
		CPU:    "500m",
		Memory: "0",
	}, nil, nil)
	if err == nil {
		t.Fatalf("expected invalid memory request to be rejected")
	}

	status, code, _, ok = apiErrorParts(err)
	if !ok {
		t.Fatalf("expected structured api error, got: %v", err)
	}
	if status != 400 {
		t.Fatalf("unexpected status: got=%d want=%d", status, 400)
	}
	if code != "invalid_memory_request" {
		t.Fatalf("unexpected code: got=%q want=%q", code, "invalid_memory_request")
	}
}

func TestParseTenantNodeAffinity(t *testing.T) {
	policy, err := parseTenantNodeAffinity("tenant-a:region=us-east,zone=a;tenant-b:pool=backend")
	if err != nil {
		t.Fatalf("parse tenant node affinity: %v", err)
	}

	if got := policy["tenant-a"]["region"]; got != "us-east" {
		t.Fatalf("unexpected selector value: got=%q", got)
	}
	if got := policy["tenant-b"]["pool"]; got != "backend" {
		t.Fatalf("unexpected selector value: got=%q", got)
	}
}
