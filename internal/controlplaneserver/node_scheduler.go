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

	selector := parseSelector(request.NodeSelector)
	requestedNode := strings.TrimSpace(request.NodeName)
	requiredMemoryBytes := requestedMemoryBytes(request)
	serviceReplicaCounts, err := server.serviceReplicaCountsForRequest(request)
	if err != nil {
		return nil, err
	}
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

		if requiredMemoryBytes > 0 && node.CapacityMemBytes > 0 {
			freeMem := node.CapacityMemBytes - node.UsedMemBytes
			if freeMem < requiredMemoryBytes {
				continue
			}
		}

		eligible = append(eligible, node)
	}

	if requestedNode != "" && len(eligible) == 0 {
		return nil, fmt.Errorf("requested node %s is not schedulable", requestedNode)
	}

	if len(eligible) == 0 {
		return nil, nil
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		leftReplicas := serviceReplicaCounts[eligible[i].Name]
		rightReplicas := serviceReplicaCounts[eligible[j].Name]
		if leftReplicas != rightReplicas {
			return leftReplicas < rightReplicas
		}

		leftScore := nodeCapacityScore(eligible[i])
		rightScore := nodeCapacityScore(eligible[j])
		if leftScore == rightScore {
			return eligible[i].Name < eligible[j].Name
		}
		return leftScore > rightScore
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

func nodeCapacityScore(node nodeRecord) float64 {
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
	return cpuWeight + memWeight
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
