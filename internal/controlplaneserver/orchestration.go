// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"unikctl.sh/internal/cli/unikctl/remove"
	"unikctl.sh/internal/cli/unikctl/run"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
)

const (
	defaultHealthPath     = "/"
	defaultHealthInterval = 1 * time.Second
	defaultHealthTimeout  = 30 * time.Second
)

func (server *Server) deploySingle(ctx context.Context, request *controlplaneapi.DeployRequest, machineName string, exclude map[string]struct{}) (string, error) {
	targetRequest := *request
	targetRequest.Name = strings.TrimSpace(machineName)

	selectedNode, err := server.selectNodeForDeploy(&targetRequest, exclude)
	if err != nil {
		return "", err
	}

	if selectedNode != nil {
		if err := server.deployToNode(ctx, *selectedNode, &targetRequest); err != nil {
			return "", err
		}
		if err := server.workloads.Upsert(targetRequest.Name, selectedNode.Name, targetRequest); err != nil {
			return "", err
		}
		return selectedNode.Name, nil
	}

	execCtx := controlplaneapi.WithServerMode(ctx)
	runOptions := &run.RunOptions{
		Detach:       true,
		Debug:        targetRequest.Debug,
		Memory:       firstNonEmpty(targetRequest.Memory, "64Mi"),
		Name:         targetRequest.Name,
		Rootfs:       targetRequest.Rootfs,
		Runtime:      targetRequest.Runtime,
		Target:       targetRequest.Target,
		Platform:     targetRequest.Platform,
		Architecture: targetRequest.Architecture,
	}

	if err := run.Run(execCtx, runOptions, targetRequest.Args...); err != nil {
		return "", err
	}

	if err := server.workloads.Upsert(targetRequest.Name, hostname(), targetRequest); err != nil {
		return "", err
	}

	return hostname(), nil
}

func (server *Server) executeServiceRollout(ctx context.Context, operationID string, request *controlplaneapi.DeployRequest) (retErr error) {
	serviceName := rolloutServiceName(request)
	desired := maxInt(request.Replicas, 1)
	strategy := normalizeRolloutStrategy(request.Strategy)
	canaryPercent := request.CanaryPercent
	if canaryPercent <= 0 {
		canaryPercent = 10
	}
	canaryCount := maxInt(1, desired*canaryPercent/100)
	canaryCount = minInt(canaryCount, desired)

	existing, exists, err := server.services.Get(serviceName)
	if err != nil {
		return err
	}
	oldMachines := []string{}
	if exists {
		oldMachines = append(oldMachines, existing.Current...)
	}

	newMachines := []string{}
	oldRemaining := append([]string{}, oldMachines...)

	updateStatus := func(phase, message, lastError string, current []string, healthy bool) {
		if err := server.services.UpsertState(serviceName, strategy, desired, current, healthy, phase, message, lastError); err != nil {
			return
		}

		switch phase {
		case "failed":
			_ = server.ops.SetState(operationID, operations.StateFailed, message)
		case "ready":
		default:
			_ = server.ops.SetState(operationID, operations.StateRunning, message)
		}
	}

	updateStatus("starting", fmt.Sprintf("rollout started for service %s (%s)", serviceName, strategy), "", oldMachines, false)

	defer func() {
		if retErr == nil {
			return
		}

		updateStatus(
			"failed",
			fmt.Sprintf("rollout failed for service %s after %d/%d healthy replicas: %v", serviceName, len(newMachines), desired, retErr),
			retErr.Error(),
			newMachines,
			false,
		)
	}()

	switch strategy {
	case "bluegreen":
		for i := 0; i < desired; i++ {
			name := rolloutMachineName(serviceName, operationID, i)
			if err := server.ensureRolloutMachine(ctx, request, name); err != nil {
				return err
			}
			if err := server.waitForMachineHealthy(ctx, name, request, healthTimeout(request)); err != nil {
				return err
			}
			newMachines = append(newMachines, name)
			updateStatus("progress", fmt.Sprintf("bluegreen rollout healthy replicas %d/%d", len(newMachines), desired), "", newMachines, false)
		}

		for _, old := range oldRemaining {
			_ = server.destroyMachine(ctx, old)
		}

	case "canary":
		for i := 0; i < canaryCount; i++ {
			name := rolloutMachineName(serviceName, operationID, i)
			if err := server.ensureRolloutMachine(ctx, request, name); err != nil {
				return err
			}
			if err := server.waitForMachineHealthy(ctx, name, request, healthTimeout(request)); err != nil {
				return err
			}
			newMachines = append(newMachines, name)
			updateStatus(
				"progress",
				fmt.Sprintf("canary phase healthy replicas %d/%d (canary target %d)", len(newMachines), desired, canaryCount),
				"",
				newMachines,
				false,
			)
		}

		for i := canaryCount; i < desired; i++ {
			name := rolloutMachineName(serviceName, operationID, i)
			if err := server.ensureRolloutMachine(ctx, request, name); err != nil {
				return err
			}
			if err := server.waitForMachineHealthy(ctx, name, request, healthTimeout(request)); err != nil {
				return err
			}
			newMachines = append(newMachines, name)
			updateStatus("progress", fmt.Sprintf("canary rollout healthy replicas %d/%d", len(newMachines), desired), "", newMachines, false)
		}

		for _, old := range oldRemaining {
			_ = server.destroyMachine(ctx, old)
		}

	default: // rolling
		maxUnavailable := request.MaxUnavailable
		if maxUnavailable <= 0 {
			maxUnavailable = 1
		}

		maxSurge := request.MaxSurge
		if maxSurge <= 0 {
			maxSurge = 1
		}

		for i := 0; i < desired; i++ {
			name := rolloutMachineName(serviceName, operationID, i)
			if err := server.ensureRolloutMachine(ctx, request, name); err != nil {
				return err
			}
			if err := server.waitForMachineHealthy(ctx, name, request, healthTimeout(request)); err != nil {
				return err
			}
			newMachines = append(newMachines, name)
			updateStatus("progress", fmt.Sprintf("rolling rollout healthy replicas %d/%d", len(newMachines), desired), "", newMachines, false)

			if (i+1)%maxSurge == 0 {
				removeCount := minInt(maxUnavailable, len(oldRemaining))
				for j := 0; j < removeCount; j++ {
					_ = server.destroyMachine(ctx, oldRemaining[0])
					oldRemaining = oldRemaining[1:]
				}
			}
		}

		for _, old := range oldRemaining {
			_ = server.destroyMachine(ctx, old)
		}
	}

	if err := server.services.UpsertState(
		serviceName,
		strategy,
		desired,
		newMachines,
		true,
		"ready",
		fmt.Sprintf("rollout healthy (%d/%d replicas)", desired, desired),
		"",
	); err != nil {
		return err
	}

	_ = server.ops.SetMachine(operationID, serviceName)
	_ = server.ops.SetState(operationID, operations.StateSubmitted, fmt.Sprintf("rollout submitted for service %s (%s, replicas=%d)", serviceName, strategy, desired))
	return nil
}

func rolloutServiceName(request *controlplaneapi.DeployRequest) string {
	if strings.TrimSpace(request.ServiceName) != "" {
		return normalizeRolloutName(strings.TrimSpace(request.ServiceName), "service")
	}

	if strings.TrimSpace(request.Name) != "" {
		return normalizeRolloutName(strings.TrimSpace(request.Name), "service")
	}

	return normalizeRolloutName(suggestMachineName(request.Args), "service")
}

func normalizeRolloutStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "bluegreen", "blue-green":
		return "bluegreen"
	case "canary":
		return "canary"
	default:
		return "rolling"
	}
}

func rolloutMachineName(service string, operationID string, index int) string {
	base := normalizeRolloutName(service, "app")

	suffix := strings.TrimSpace(operationID)
	if suffix == "" {
		suffix = strconv.FormatInt(time.Now().UTC().Unix()%100000, 10)
	}
	suffix = strings.TrimPrefix(suffix, "op-")
	suffix = strings.ReplaceAll(suffix, "/", "-")
	suffix = strings.ReplaceAll(suffix, " ", "-")
	suffix = normalizeRolloutName(suffix, "r")

	if len(base) > 24 {
		base = base[:24]
		base = strings.Trim(base, "-")
		if base == "" {
			base = "app"
		}
	}

	if len(suffix) > 24 {
		suffix = suffix[:24]
		suffix = strings.Trim(suffix, "-")
		if suffix == "" {
			suffix = "r"
		}
	}

	return fmt.Sprintf("%s-r%s-%d", base, suffix, index)
}

func normalizeRolloutName(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}

	replacer := strings.NewReplacer(
		" ", "-",
		"_", "-",
		".", "-",
		":", "-",
		"/", "-",
		"\\", "-",
	)
	value = replacer.Replace(value)

	normalized := make([]rune, 0, len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			normalized = append(normalized, r)
		}
	}

	result := strings.Trim(string(normalized), "-")
	if result == "" {
		return fallback
	}
	return result
}

func requestWantsRollout(request *controlplaneapi.DeployRequest) bool {
	if request == nil {
		return false
	}

	if strings.TrimSpace(request.ServiceName) != "" {
		return true
	}

	if request.Replicas > 1 {
		return true
	}

	return strings.TrimSpace(request.Strategy) != ""
}

func (server *Server) ensureRolloutMachine(ctx context.Context, request *controlplaneapi.DeployRequest, machineName string) error {
	machine, found, err := server.findMachine(ctx, machineName)
	if err != nil {
		return err
	}

	if found {
		state := strings.ToLower(strings.TrimSpace(string(machine.State)))
		switch state {
		case "running", "created", "exited":
			return nil
		}
	}

	_, err = server.deploySingle(ctx, request, machineName, map[string]struct{}{})
	return err
}

func (server *Server) waitForMachineHealthy(ctx context.Context, machineName string, request *controlplaneapi.DeployRequest, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		machine, found, err := server.findMachine(ctx, machineName)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if !found {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		state := strings.ToLower(strings.TrimSpace(string(machine.State)))
		if state == "failed" || state == "errored" {
			return fmt.Errorf("machine %s entered failed state", machineName)
		}
		if state != "running" && state != "exited" && state != "created" {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if !hasHealthCheck(request) {
			if state == "running" || state == "exited" {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		ok := server.checkHTTPHealth(machine, request)
		if ok {
			return nil
		}

		interval := healthInterval(request)
		time.Sleep(interval)
	}

	return fmt.Errorf("timeout waiting for machine %s to become healthy", machineName)
}

func (server *Server) findMachine(ctx context.Context, machineName string) (machineStatus, bool, error) {
	machines, err := server.aggregateMachines(ctx)
	if err != nil {
		return machineStatus{}, false, err
	}

	for _, machine := range machines {
		if machine.Name == machineName || machine.ID == machineName {
			return machine, true, nil
		}
	}

	return machineStatus{}, false, nil
}

func hasHealthCheck(request *controlplaneapi.DeployRequest) bool {
	if request == nil {
		return false
	}
	if strings.TrimSpace(request.HealthCheck.Path) != "" {
		return true
	}
	if request.HealthCheck.Port > 0 {
		return true
	}
	return false
}

func healthPath(request *controlplaneapi.DeployRequest) string {
	if request == nil || strings.TrimSpace(request.HealthCheck.Path) == "" {
		return defaultHealthPath
	}
	path := strings.TrimSpace(request.HealthCheck.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func healthInterval(request *controlplaneapi.DeployRequest) time.Duration {
	if request == nil || request.HealthCheck.IntervalSeconds <= 0 {
		return defaultHealthInterval
	}
	return time.Duration(request.HealthCheck.IntervalSeconds) * time.Second
}

func healthTimeout(request *controlplaneapi.DeployRequest) time.Duration {
	if request == nil || request.HealthCheck.TimeoutSeconds <= 0 {
		return defaultHealthTimeout
	}
	return time.Duration(request.HealthCheck.TimeoutSeconds) * time.Second
}

func (server *Server) checkHTTPHealth(machine machineStatus, request *controlplaneapi.DeployRequest) bool {
	host, port, ok := server.machineHealthEndpoint(machine, request)
	if !ok {
		return false
	}

	endpoint := fmt.Sprintf("http://%s:%d%s", host, port, healthPath(request))
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Get(endpoint)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 400
}

func (server *Server) machineHealthEndpoint(machine machineStatus, request *controlplaneapi.DeployRequest) (string, int, bool) {
	port := request.HealthCheck.Port
	host := "127.0.0.1"
	if machine.Node != "" && machine.Node != hostname() {
		if node, ok, _ := server.nodes.Get(machine.Node); ok {
			if parsed, err := url.Parse(strings.TrimSpace(node.AgentURL)); err == nil {
				host = firstNonEmpty(parsed.Hostname(), host)
			}
		}
	}

	if port > 0 {
		return host, port, true
	}

	for _, token := range strings.Split(machine.Ports, ",") {
		left, _, ok := strings.Cut(strings.TrimSpace(token), "->")
		if !ok {
			continue
		}

		left = strings.TrimSpace(left)
		h, p, err := net.SplitHostPort(left)
		if err != nil {
			continue
		}

		parsedPort, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || parsedPort <= 0 {
			continue
		}

		h = strings.TrimSpace(h)
		if h != "" && h != "0.0.0.0" {
			host = h
		}
		return host, parsedPort, true
	}

	return "", 0, false
}

func (server *Server) destroyMachine(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	workload, ok, err := server.workloads.Get(name)
	if err != nil {
		return err
	}

	if ok && workload.Node != "" && workload.Node != hostname() {
		node, found, err := server.nodes.Get(workload.Node)
		if err != nil {
			return err
		}
		if found {
			if err := server.destroyOnNode(ctx, node, &controlplaneapi.DestroyRequest{Names: []string{name}}); err != nil {
				return err
			}
			_ = server.workloads.RemoveMachines(name)
			return nil
		}
	}

	execCtx := controlplaneapi.WithServerMode(ctx)
	if err := remove.Remove(execCtx, &remove.RemoveOptions{All: false}, name); err != nil {
		return err
	}
	_ = server.workloads.RemoveMachines(name)
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
