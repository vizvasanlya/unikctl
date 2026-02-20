// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"fmt"
	"strings"
)

func (server *Server) renderResourceMetrics() string {
	if server == nil || server.workloads == nil {
		return ""
	}

	workloads, err := server.workloads.List()
	if err != nil {
		return ""
	}

	requestedCPU := int64(0)
	requestedMemory := int64(0)
	actualRSS := int64(0)
	hostOverhead := int64(0)
	restartTotal := int64(0)
	stealTotalMillis := int64(0)
	noisyNeighbors := int64(0)
	maxMemoryPressure := float64(0)

	for _, record := range workloads {
		requestedCPU += record.RequestedCPUMilli
		requestedMemory += record.RequestedMemBytes
		actualRSS += maxInt64(record.ActualRSSBytes, 0)
		hostOverhead += maxInt64(record.HostOverheadBytes, 0)
		restartTotal += maxInt64(record.RestartCount, 0)
		stealTotalMillis += maxInt64(record.StealTimeMillis, 0)

		if record.MemoryPressurePct > maxMemoryPressure {
			maxMemoryPressure = clampFloat(record.MemoryPressurePct, 0, 1)
		}
		if record.NoisyNeighborScore >= 1.0 {
			noisyNeighbors++
		}
	}

	maxNodeMemoryPressure := float64(0)
	maxNodeCPUPressure := float64(0)
	if server.nodes != nil {
		if nodes, err := server.nodes.List(); err == nil {
			for _, node := range nodes {
				if node.CapacityMemBytes > 0 {
					pressure := float64(node.UsedMemBytes) / float64(node.CapacityMemBytes)
					pressure = clampFloat(pressure, 0, 1)
					if pressure > maxNodeMemoryPressure {
						maxNodeMemoryPressure = pressure
					}
				}

				if node.CapacityCPUMilli > 0 {
					pressure := float64(node.UsedCPUMilli) / float64(node.CapacityCPUMilli)
					pressure = clampFloat(pressure, 0, 1)
					if pressure > maxNodeCPUPressure {
						maxNodeCPUPressure = pressure
					}
				}
			}
		}
	}

	builder := strings.Builder{}
	builder.WriteString("# HELP unikctl_control_plane_requested_cpu_milli_total Total requested CPU across tracked workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_requested_cpu_milli_total gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_requested_cpu_milli_total %d\n", requestedCPU))
	builder.WriteString("# HELP unikctl_control_plane_requested_memory_bytes_total Total requested memory across tracked workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_requested_memory_bytes_total gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_requested_memory_bytes_total %d\n", requestedMemory))
	builder.WriteString("# HELP unikctl_control_plane_actual_rss_bytes_total Total measured RSS across tracked workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_actual_rss_bytes_total gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_actual_rss_bytes_total %d\n", actualRSS))
	builder.WriteString("# HELP unikctl_control_plane_host_overhead_bytes_total Total estimated host overhead across tracked workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_host_overhead_bytes_total gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_host_overhead_bytes_total %d\n", hostOverhead))
	builder.WriteString("# HELP unikctl_control_plane_restart_total Total restart/reconcile attempts recorded for workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_restart_total counter\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_restart_total %d\n", restartTotal))
	builder.WriteString("# HELP unikctl_control_plane_steal_time_millis_total Total tracked steal time in milliseconds.\n")
	builder.WriteString("# TYPE unikctl_control_plane_steal_time_millis_total counter\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_steal_time_millis_total %d\n", stealTotalMillis))
	builder.WriteString("# HELP unikctl_control_plane_noisy_neighbor_total Number of workloads exceeding noisy-neighbor score threshold.\n")
	builder.WriteString("# TYPE unikctl_control_plane_noisy_neighbor_total gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_noisy_neighbor_total %d\n", noisyNeighbors))
	builder.WriteString("# HELP unikctl_control_plane_memory_pressure_ratio_max Maximum memory pressure ratio observed among workloads.\n")
	builder.WriteString("# TYPE unikctl_control_plane_memory_pressure_ratio_max gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_memory_pressure_ratio_max %.6f\n", maxMemoryPressure))
	builder.WriteString("# HELP unikctl_control_plane_node_memory_pressure_ratio_max Maximum node memory pressure ratio.\n")
	builder.WriteString("# TYPE unikctl_control_plane_node_memory_pressure_ratio_max gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_node_memory_pressure_ratio_max %.6f\n", maxNodeMemoryPressure))
	builder.WriteString("# HELP unikctl_control_plane_node_cpu_pressure_ratio_max Maximum node CPU pressure ratio.\n")
	builder.WriteString("# TYPE unikctl_control_plane_node_cpu_pressure_ratio_max gauge\n")
	builder.WriteString(fmt.Sprintf("unikctl_control_plane_node_cpu_pressure_ratio_max %.6f\n", maxNodeCPUPressure))
	return builder.String()
}
