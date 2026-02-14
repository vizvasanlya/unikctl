// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneapi

import "time"

type DeployRequest struct {
	Args               []string `json:"args"`
	Debug              bool     `json:"debug,omitempty"`
	Memory             string   `json:"memory,omitempty"`
	Name               string   `json:"name,omitempty"`
	Rootfs             string   `json:"rootfs,omitempty"`
	Runtime            string   `json:"runtime,omitempty"`
	Target             string   `json:"target,omitempty"`
	Platform           string   `json:"platform,omitempty"`
	Architecture       string   `json:"architecture,omitempty"`
	ArtifactID         string   `json:"artifact_id,omitempty"`
	ArtifactPath       string   `json:"artifact_path,omitempty"`
	RootfsArtifactID   string   `json:"rootfs_artifact_id,omitempty"`
	RootfsArtifactPath string   `json:"rootfs_artifact_path,omitempty"`
	NodeName           string   `json:"node_name,omitempty"`
	NodeSelector       []string `json:"node_selector,omitempty"`
	ServiceName        string   `json:"service_name,omitempty"`
	Replicas           int      `json:"replicas,omitempty"`
	Strategy           string   `json:"strategy,omitempty"`
	MaxUnavailable     int      `json:"max_unavailable,omitempty"`
	MaxSurge           int      `json:"max_surge,omitempty"`
	CanaryPercent      int      `json:"canary_percent,omitempty"`
	HealthCheck        struct {
		Path            string `json:"path,omitempty"`
		Port            int    `json:"port,omitempty"`
		IntervalSeconds int    `json:"interval_seconds,omitempty"`
		TimeoutSeconds  int    `json:"timeout_seconds,omitempty"`
	} `json:"health_check,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	TraceID        string `json:"trace_id,omitempty"`
}

type DeployResponse struct {
	OperationID string `json:"operation_id"`
	TraceID     string `json:"trace_id,omitempty"`
	Reused      bool   `json:"reused,omitempty"`
}

type DestroyRequest struct {
	Names          []string `json:"names,omitempty"`
	All            bool     `json:"all,omitempty"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	TraceID        string   `json:"trace_id,omitempty"`
}

type DestroyResponse struct {
	OperationID string `json:"operation_id"`
	TraceID     string `json:"trace_id,omitempty"`
	Reused      bool   `json:"reused,omitempty"`
}

type ArtifactUploadResponse struct {
	ArtifactID string `json:"artifact_id"`
}

type Operation struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Target    string    `json:"target,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	Message   string    `json:"message,omitempty"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Machine struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Node      string    `json:"node,omitempty"`
	Kernel    string    `json:"kernel,omitempty"`
	Args      string    `json:"args,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	State     string    `json:"state"`
	Mem       string    `json:"mem,omitempty"`
	Ports     string    `json:"ports,omitempty"`
	Pid       int32     `json:"pid,omitempty"`
	Arch      string    `json:"arch,omitempty"`
	Plat      string    `json:"plat,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
}

type StatusResponse struct {
	Operations []Operation `json:"operations"`
	Machines   []Machine   `json:"machines"`
	Nodes      []Node      `json:"nodes"`
	Services   []Service   `json:"services"`
}

type Service struct {
	Name        string    `json:"name"`
	Strategy    string    `json:"strategy,omitempty"`
	Phase       string    `json:"phase,omitempty"`
	Message     string    `json:"message,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Desired     int       `json:"desired"`
	Ready       int       `json:"ready"`
	Machines    []string  `json:"machines,omitempty"`
	LastHealthy time.Time `json:"last_healthy,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type Node struct {
	Name             string            `json:"name"`
	Address          string            `json:"address"`
	AgentURL         string            `json:"agent_url,omitempty"`
	State            string            `json:"state"`
	Cordoned         bool              `json:"cordoned,omitempty"`
	Draining         bool              `json:"draining,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	CapacityCPUMilli int64             `json:"capacity_cpu_milli,omitempty"`
	CapacityMemBytes int64             `json:"capacity_mem_bytes,omitempty"`
	UsedCPUMilli     int64             `json:"used_cpu_milli,omitempty"`
	UsedMemBytes     int64             `json:"used_mem_bytes,omitempty"`
	Machines         int               `json:"machines"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	TraceID string `json:"trace_id,omitempty"`
}

type NodeRegisterRequest struct {
	Name             string            `json:"name"`
	Address          string            `json:"address"`
	AgentURL         string            `json:"agent_url"`
	AgentToken       string            `json:"agent_token,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	CapacityCPUMilli int64             `json:"capacity_cpu_milli,omitempty"`
	CapacityMemBytes int64             `json:"capacity_mem_bytes,omitempty"`
	UsedCPUMilli     int64             `json:"used_cpu_milli,omitempty"`
	UsedMemBytes     int64             `json:"used_mem_bytes,omitempty"`
	Machines         int               `json:"machines,omitempty"`
}

type NodeHeartbeatRequest struct {
	Name             string            `json:"name"`
	Address          string            `json:"address,omitempty"`
	AgentURL         string            `json:"agent_url,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	CapacityCPUMilli int64             `json:"capacity_cpu_milli,omitempty"`
	CapacityMemBytes int64             `json:"capacity_mem_bytes,omitempty"`
	UsedCPUMilli     int64             `json:"used_cpu_milli,omitempty"`
	UsedMemBytes     int64             `json:"used_mem_bytes,omitempty"`
	Machines         int               `json:"machines,omitempty"`
}

type NodeActionResponse struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Message  string `json:"message,omitempty"`
	Migrated int    `json:"migrated,omitempty"`
	Failed   int    `json:"failed,omitempty"`
}
