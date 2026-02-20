// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
)

func (server *Server) nodeClient(ctx context.Context, node nodeRecord) (*controlplaneapi.Client, error) {
	controlPlaneCfg := config.G[config.KraftKit](ctx).ControlPlane
	authToken := strings.TrimSpace(node.AgentToken)
	if authToken == "" {
		authToken = strings.TrimSpace(server.authToken)
	}

	return controlplaneapi.NewClient(node.AgentURL, controlplaneapi.ClientOptions{
		AuthToken:   authToken,
		TLSCAFile:   controlPlaneCfg.TLSCAFile,
		TLSInsecure: controlPlaneCfg.TLSInsecure,
		Timeout:     30 * time.Second,
	})
}

func (server *Server) selectNodeForDeploy(request *controlplaneapi.DeployRequest, exclude map[string]struct{}) (*nodeRecord, error) {
	if server.nodes == nil {
		return nil, nil
	}

	if request == nil {
		request = &controlplaneapi.DeployRequest{}
	}

	if err := server.nodes.MarkOfflineStale(nodeHeartbeatStaleAfter); err != nil {
		return nil, err
	}

	nodes, err := server.nodes.List()
	if err != nil {
		return nil, err
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	effectiveRequest := *request
	effectiveRequest.NodeSelector = append([]string{}, request.NodeSelector...)
	if selector := tenantAffinitySelector(server.tenantNodeAffinity, effectiveRequest.Tenant); len(selector) > 0 {
		effectiveRequest.NodeSelector = append(effectiveRequest.NodeSelector, selector...)
	}

	serviceReplicaCounts, err := server.serviceReplicaCountsForRequest(&effectiveRequest)
	if err != nil {
		return nil, err
	}

	return selectEligibleNode(nodes, &effectiveRequest, exclude, serviceReplicaCounts)
}

func selectEligibleNode(nodes []nodeRecord, request *controlplaneapi.DeployRequest, exclude map[string]struct{}, serviceReplicaCounts map[string]int) (*nodeRecord, error) {
	if request == nil {
		request = &controlplaneapi.DeployRequest{}
	}

	if exclude == nil {
		exclude = map[string]struct{}{}
	}

	if serviceReplicaCounts == nil {
		serviceReplicaCounts = map[string]int{}
	}

	selector := parseSelector(request.NodeSelector)
	requestedNode := strings.TrimSpace(request.NodeName)
	tenant := normalizeTenant(request.Tenant)
	requiredMemoryBytes, requiredCPUMilli, err := parseRequestedResourcesStrict(request)
	if err != nil {
		return nil, err
	}
	strategy := schedulerStrategyFromEnv()
	eligible := make([]nodeRecord, 0, len(nodes))
	for _, node := range nodes {
		if _, skip := exclude[node.Name]; skip {
			continue
		}

		if requestedNode != "" && node.Name != requestedNode {
			continue
		}

		if node.State != nodeStateReady || node.Cordoned || node.Draining {
			continue
		}

		if node.AgentURL == "" {
			continue
		}

		if !nodeMatchesSelector(node, selector) {
			continue
		}

		if !nodeAllowsTenant(node, tenant) {
			continue
		}

		if requiredMemoryBytes > 0 && node.CapacityMemBytes > 0 {
			freeMem := node.CapacityMemBytes - node.UsedMemBytes
			if freeMem < requiredMemoryBytes {
				continue
			}
		}

		if requiredCPUMilli > 0 && node.CapacityCPUMilli > 0 {
			freeCPU := node.CapacityCPUMilli - node.UsedCPUMilli
			if freeCPU < requiredCPUMilli {
				continue
			}
		}

		eligible = append(eligible, node)
	}

	if requestedNode != "" && len(eligible) == 0 {
		return nil, newAdmissionError(
			"requested_node_unschedulable",
			fmt.Sprintf("requested node %s is not schedulable for requested resources", requestedNode),
		)
	}

	if len(eligible) == 0 {
		return nil, newAdmissionError(
			"admission_rejected_capacity",
			formatCapacityRequirement(requiredMemoryBytes, requiredCPUMilli),
		)
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		leftReplicas := serviceReplicaCounts[eligible[i].Name]
		rightReplicas := serviceReplicaCounts[eligible[j].Name]
		if leftReplicas != rightReplicas {
			return leftReplicas < rightReplicas
		}

		leftScore := nodeCapacityScore(eligible[i], strategy)
		rightScore := nodeCapacityScore(eligible[j], strategy)
		if leftScore == rightScore {
			return eligible[i].Name < eligible[j].Name
		}
		switch strategy {
		case schedulerStrategyBinpack:
			return leftScore < rightScore
		default:
			return leftScore > rightScore
		}
	})

	chosen := eligible[0]
	return &chosen, nil
}

func (server *Server) serviceReplicaCountsForRequest(request *controlplaneapi.DeployRequest) (map[string]int, error) {
	counts := map[string]int{}
	if request == nil {
		return counts, nil
	}

	serviceName := rolloutServiceName(request)
	if strings.TrimSpace(serviceName) == "" {
		return counts, nil
	}

	service, found, err := server.services.Get(serviceName)
	if err != nil {
		return nil, err
	}
	if !found {
		return counts, nil
	}

	for _, machine := range service.Current {
		workload, ok, err := server.workloads.Get(machine)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		node := strings.TrimSpace(workload.Node)
		if node == "" {
			continue
		}
		counts[node]++
	}

	return counts, nil
}

func requestedMemoryBytes(request *controlplaneapi.DeployRequest) int64 {
	if request == nil {
		return 0
	}

	memory := strings.TrimSpace(request.Memory)
	if memory == "" {
		memory = "64Mi"
	}

	quantity, err := resource.ParseQuantity(memory)
	if err != nil {
		return 0
	}

	value := quantity.Value()
	if value < 0 {
		return 0
	}
	return value
}

func requestedCPUMilli(request *controlplaneapi.DeployRequest) int64 {
	if request == nil {
		return 1000
	}

	cpu := strings.TrimSpace(request.CPU)
	if cpu == "" {
		cpu = "1"
	}

	quantity, err := resource.ParseQuantity(cpu)
	if err != nil {
		return 1000
	}

	if quantity.MilliValue() <= 0 {
		return 1000
	}

	return quantity.MilliValue()
}

func parseRequestedResourcesStrict(request *controlplaneapi.DeployRequest) (int64, int64, error) {
	if request == nil {
		request = &controlplaneapi.DeployRequest{}
	}

	memoryText := strings.TrimSpace(request.Memory)
	if memoryText == "" {
		memoryText = "64Mi"
	}

	cpuText := strings.TrimSpace(request.CPU)
	if cpuText == "" {
		cpuText = "1"
	}

	memoryQuantity, err := resource.ParseQuantity(memoryText)
	if err != nil {
		return 0, 0, newAPIError(
			400,
			"invalid_memory_request",
			fmt.Sprintf("invalid memory request %q: %v", memoryText, err),
		)
	}

	cpuQuantity, err := resource.ParseQuantity(cpuText)
	if err != nil {
		return 0, 0, newAPIError(
			400,
			"invalid_cpu_request",
			fmt.Sprintf("invalid CPU request %q: %v", cpuText, err),
		)
	}

	if memoryQuantity.Value() <= 0 {
		return 0, 0, newAPIError(
			400,
			"invalid_memory_request",
			"memory request must be greater than zero",
		)
	}

	if cpuQuantity.MilliValue() <= 0 {
		return 0, 0, newAPIError(
			400,
			"invalid_cpu_request",
			"CPU request must be greater than zero",
		)
	}

	return memoryQuantity.Value(), cpuQuantity.MilliValue(), nil
}

func (server *Server) deployToNode(ctx context.Context, node nodeRecord, request *controlplaneapi.DeployRequest) error {
	client, err := server.nodeClient(ctx, node)
	if err != nil {
		return err
	}

	deployRequest := *request
	if err := stageDeployRequestForNode(ctx, client, &deployRequest); err != nil {
		return err
	}

	response, err := client.Deploy(ctx, deployRequest)
	if err != nil {
		return err
	}
	if strings.TrimSpace(response.OperationID) == "" {
		return fmt.Errorf("node %s returned empty operation ID", node.Name)
	}

	return nil
}

func (server *Server) destroyOnNode(ctx context.Context, node nodeRecord, request *controlplaneapi.DestroyRequest) error {
	client, err := server.nodeClient(ctx, node)
	if err != nil {
		return err
	}

	response, err := client.Destroy(ctx, *request)
	if err != nil {
		return err
	}
	if strings.TrimSpace(response.OperationID) == "" {
		return fmt.Errorf("node %s returned empty operation ID", node.Name)
	}

	return nil
}

func (server *Server) listNodeMachines(ctx context.Context, node nodeRecord) ([]machineStatus, error) {
	client, err := server.nodeClient(ctx, node)
	if err != nil {
		return nil, err
	}

	status, err := client.Status(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]machineStatus, 0, len(status.Machines))
	for _, machine := range status.Machines {
		out = append(out, machineStatus{
			ID:        machine.ID,
			Name:      machine.Name,
			Node:      node.Name,
			Kernel:    machine.Kernel,
			Args:      machine.Args,
			CreatedAt: machine.CreatedAt,
			State:     parseMachineState(machine.State),
			Mem:       machine.Mem,
			Ports:     machine.Ports,
			Pid:       machine.Pid,
			Arch:      machine.Arch,
			Plat:      machine.Plat,
			IPs:       append([]string{}, machine.IPs...),
		})
	}

	return out, nil
}

func stageDeployRequestForNode(ctx context.Context, client *controlplaneapi.Client, request *controlplaneapi.DeployRequest) error {
	if request == nil {
		return fmt.Errorf("deploy request is required")
	}

	request.ArtifactID = ""
	request.ArtifactPath = ""
	request.RootfsArtifactID = ""
	request.RootfsArtifactPath = ""

	if len(request.Args) > 0 {
		sourcePath := strings.TrimSpace(request.Args[0])
		if sourcePath != "" {
			artifactID, artifactPath, err := uploadPathToRemoteArtifact(ctx, client, sourcePath)
			if err != nil {
				return err
			}

			if artifactID != "" {
				request.ArtifactID = artifactID
				request.ArtifactPath = artifactPath
			}
		}
	}

	if strings.TrimSpace(request.Rootfs) != "" {
		artifactID, artifactPath, err := uploadPathToRemoteArtifact(ctx, client, request.Rootfs)
		if err != nil {
			return err
		}

		if artifactID != "" {
			request.RootfsArtifactID = artifactID
			request.RootfsArtifactPath = artifactPath
		}
	}

	return nil
}

func uploadPathToRemoteArtifact(ctx context.Context, client *controlplaneapi.Client, path string) (string, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", "", nil
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolving artifact path: %w", err)
	}

	artifactPath := "."
	if !info.IsDir() {
		artifactPath = filepath.Base(absolutePath)
	}

	artifactID, err := client.UploadSource(ctx, absolutePath)
	if err != nil {
		return "", "", err
	}

	return artifactID, artifactPath, nil
}

func parseSelector(raw []string) map[string]string {
	selector := map[string]string{}
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			selector[strings.TrimSpace(entry)] = ""
			continue
		}

		selector[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return selector
}

func nodeMatchesSelector(node nodeRecord, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}

	for key, expectedValue := range selector {
		actualValue, ok := node.Labels[key]
		if !ok {
			return false
		}
		if expectedValue != "" && actualValue != expectedValue {
			return false
		}
	}

	return true
}

type schedulerStrategy string

const (
	schedulerStrategySpread         schedulerStrategy = "spread"
	schedulerStrategyBinpack        schedulerStrategy = "binpack"
	schedulerStrategyMemoryPriority schedulerStrategy = "memory-priority"
	schedulerStrategyCPUPriority    schedulerStrategy = "cpu-priority"
)

func schedulerStrategyFromEnv() schedulerStrategy {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("UNIKCTL_SCHEDULER_STRATEGY"))) {
	case string(schedulerStrategyBinpack):
		return schedulerStrategyBinpack
	case string(schedulerStrategyMemoryPriority):
		return schedulerStrategyMemoryPriority
	case string(schedulerStrategyCPUPriority):
		return schedulerStrategyCPUPriority
	default:
		return schedulerStrategySpread
	}
}

func nodeCapacityScore(node nodeRecord, strategy schedulerStrategy) float64 {
	freeCPU := float64(node.CapacityCPUMilli - node.UsedCPUMilli)
	if freeCPU < 0 {
		freeCPU = 0
	}

	freeMem := float64(node.CapacityMemBytes - node.UsedMemBytes)
	if freeMem < 0 {
		freeMem = 0
	}

	cpuWeight := freeCPU
	memWeight := freeMem / float64(1024*1024)

	switch strategy {
	case schedulerStrategyMemoryPriority:
		return memWeight*2 + cpuWeight
	case schedulerStrategyCPUPriority:
		return cpuWeight*2 + memWeight
	case schedulerStrategyBinpack:
		return cpuWeight + memWeight
	default: // spread
		return cpuWeight + memWeight
	}
}

func normalizeTenant(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return strings.ToLower(value)
}

func nodeAllowsTenant(node nodeRecord, tenant string) bool {
	if tenant == "" {
		return true
	}

	nodeTenant := strings.ToLower(strings.TrimSpace(node.Labels["tenant"]))
	if nodeTenant == "" || nodeTenant == "shared" {
		return true
	}

	return nodeTenant == tenant
}

func parseTenantNodeAffinity(raw string) (map[string]map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]map[string]string{}, nil
	}

	policy := map[string]map[string]string{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		tenantRaw, selectorsRaw, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("invalid tenant node affinity entry %q: expected tenant:key=value,key=value", entry)
		}

		tenant := normalizeTenant(tenantRaw)
		if tenant == "" {
			return nil, fmt.Errorf("tenant name cannot be empty in node affinity policy")
		}

		selector := map[string]string{}
		for _, pair := range strings.Split(selectorsRaw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return nil, fmt.Errorf("invalid tenant node affinity selector %q for tenant %s", pair, tenant)
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				return nil, fmt.Errorf("tenant node affinity selectors must include key=value for tenant %s", tenant)
			}
			selector[key] = value
		}

		if len(selector) == 0 {
			return nil, fmt.Errorf("tenant node affinity for %s must include at least one selector", tenant)
		}
		policy[tenant] = selector
	}

	return policy, nil
}

func tenantAffinitySelector(policy map[string]map[string]string, tenant string) []string {
	if len(policy) == 0 {
		return nil
	}

	tenant = normalizeTenant(tenant)
	selector, ok := policy[tenant]
	if !ok {
		selector, ok = policy["default"]
		if !ok {
			return nil
		}
	}

	return labelsToSelector(selector)
}

func labelsToSelector(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}

	selector := make([]string, 0, len(labels))
	for key, value := range labels {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		selector = append(selector, key+"="+strings.TrimSpace(value))
	}

	sort.Strings(selector)
	return selector
}

func parseInt64Env(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}

	return value
}
