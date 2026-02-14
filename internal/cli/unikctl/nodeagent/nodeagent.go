// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package nodeagent

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/controlplaneserver"
	"unikctl.sh/log"
	mplatform "unikctl.sh/machine/platform"
)

type NodeAgentOptions struct{}

const (
	defaultNodeAgentListen            = "127.0.0.1:7780"
	defaultNodeAgentHeartbeatInterval = 5 * time.Second
	defaultNodeCapacityMemBytes       = int64(8 * 1024 * 1024 * 1024)
)

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&NodeAgentOptions{}, cobra.Command{
		Use:    "node-agent",
		Short:  "Run node agent service",
		Hidden: true,
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *NodeAgentOptions) Run(ctx context.Context, _ []string) error {
	listen := strings.TrimSpace(os.Getenv("UNIKCTL_NODE_AGENT_LISTEN"))
	if listen == "" {
		listen = defaultNodeAgentListen
	}

	advertiseURL := strings.TrimSpace(os.Getenv("UNIKCTL_NODE_AGENT_ADVERTISE_URL"))
	if advertiseURL == "" {
		advertiseURL = "http://" + listen
	}

	nodeName := strings.TrimSpace(os.Getenv("UNIKCTL_NODE_AGENT_NAME"))
	if nodeName == "" {
		nodeName = hostname()
	}

	controlPlaneURL := firstNonEmpty(
		os.Getenv("UNIKCTL_NODE_CONTROL_PLANE_URL"),
		os.Getenv("UNIKCTL_CONTROL_PLANE_URL"),
	)
	controlPlaneToken := firstNonEmpty(
		os.Getenv("UNIKCTL_NODE_CONTROL_PLANE_TOKEN"),
		os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN"),
	)
	agentToken := firstNonEmpty(
		os.Getenv("UNIKCTL_NODE_AGENT_TOKEN"),
		os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN"),
	)

	interval := parseDurationEnv("UNIKCTL_NODE_AGENT_HEARTBEAT_INTERVAL", defaultNodeAgentHeartbeatInterval)
	capacityCPU := parseInt64Env("UNIKCTL_NODE_AGENT_CAPACITY_CPU_MILLI", int64(runtime.NumCPU()*1000))
	capacityMem := parseInt64Env("UNIKCTL_NODE_AGENT_CAPACITY_MEM_BYTES", defaultNodeCapacityMemBytes)
	labels := parseLabels(os.Getenv("UNIKCTL_NODE_AGENT_LABELS"))

	_ = os.Setenv("UNIKCTL_NODE_AGENT_MODE", "1")
	if strings.TrimSpace(agentToken) != "" {
		_ = os.Setenv("UNIKCTL_CONTROL_PLANE_TOKEN", strings.TrimSpace(agentToken))
	}
	_ = os.Setenv("UNIKCTL_CONTROL_PLANE_LISTEN", listen)

	workers := config.G[config.KraftKit](ctx).ControlPlane.MaxConcurrentOps
	server, err := controlplaneserver.New(ctx, listen, workers)
	if err != nil {
		return err
	}

	if strings.TrimSpace(controlPlaneURL) != "" {
		go heartbeatLoop(ctx, heartbeatConfig{
			NodeName:          nodeName,
			NodeAddress:       listen,
			AdvertiseURL:      advertiseURL,
			AgentToken:        agentToken,
			ControlPlaneURL:   controlPlaneURL,
			ControlPlaneToken: controlPlaneToken,
			Labels:            labels,
			CapacityCPU:       capacityCPU,
			CapacityMem:       capacityMem,
			Interval:          interval,
		})
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"listen":             listen,
		"node_name":          nodeName,
		"advertise_url":      advertiseURL,
		"control_plane_url":  controlPlaneURL,
		"heartbeat_interval": interval.String(),
	}).Info("starting node agent")

	return server.Run()
}

type heartbeatConfig struct {
	NodeName          string
	NodeAddress       string
	AdvertiseURL      string
	AgentToken        string
	ControlPlaneURL   string
	ControlPlaneToken string
	Labels            map[string]string
	CapacityCPU       int64
	CapacityMem       int64
	Interval          time.Duration
}

func heartbeatLoop(ctx context.Context, cfg heartbeatConfig) {
	client, err := controlplaneapi.NewClient(cfg.ControlPlaneURL, controlplaneapi.ClientOptions{
		AuthToken: strings.TrimSpace(cfg.ControlPlaneToken),
		Timeout:   10 * time.Second,
	})
	if err != nil {
		log.G(ctx).WithError(err).Error("could not create control-plane client for node heartbeat")
		return
	}

	register := func() {
		usedCPU, usedMem, machines := collectNodeUsage(ctx)
		_, err := client.RegisterNode(ctx, controlplaneapi.NodeRegisterRequest{
			Name:             cfg.NodeName,
			Address:          cfg.NodeAddress,
			AgentURL:         cfg.AdvertiseURL,
			AgentToken:       strings.TrimSpace(cfg.AgentToken),
			Labels:           cfg.Labels,
			CapacityCPUMilli: cfg.CapacityCPU,
			CapacityMemBytes: cfg.CapacityMem,
			UsedCPUMilli:     usedCPU,
			UsedMemBytes:     usedMem,
			Machines:         machines,
		})
		if err != nil {
			log.G(ctx).WithError(err).Warn("node register failed")
		}
	}

	heartbeat := func() {
		usedCPU, usedMem, machines := collectNodeUsage(ctx)
		_, err := client.HeartbeatNode(ctx, controlplaneapi.NodeHeartbeatRequest{
			Name:             cfg.NodeName,
			Address:          cfg.NodeAddress,
			AgentURL:         cfg.AdvertiseURL,
			Labels:           cfg.Labels,
			CapacityCPUMilli: cfg.CapacityCPU,
			CapacityMemBytes: cfg.CapacityMem,
			UsedCPUMilli:     usedCPU,
			UsedMemBytes:     usedMem,
			Machines:         machines,
		})
		if err != nil {
			log.G(ctx).WithError(err).Warn("node heartbeat failed")
		}
	}

	register()
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeat()
		}
	}
}

func collectNodeUsage(ctx context.Context) (int64, int64, int) {
	controller, err := mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	if err != nil {
		return 0, 0, 0
	}

	list, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return 0, 0, 0
	}

	usedCPUMilli := int64(0)
	usedMemBytes := int64(0)
	count := 0
	for _, machine := range list.Items {
		if machine.Status.State != machineapi.MachineStateRunning && machine.Status.State != machineapi.MachineStateCreated {
			continue
		}

		count++
		if qty, ok := machine.Spec.Resources.Requests[corev1.ResourceMemory]; ok {
			usedMemBytes += qty.Value()
		}

		if qty, ok := machine.Spec.Resources.Requests[corev1.ResourceCPU]; ok {
			usedCPUMilli += qty.MilliValue()
		} else {
			usedCPUMilli += 1000
		}
	}

	return usedCPUMilli, usedMemBytes, count
}

func parseLabels(raw string) map[string]string {
	labels := map[string]string{}
	for _, pair := range strings.Split(strings.TrimSpace(raw), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		key, value, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		if !ok {
			labels[key] = ""
			continue
		}

		labels[key] = strings.TrimSpace(value)
	}
	return labels
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

func parseDurationEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	value, err := time.ParseDuration(raw)
	if err == nil && value > 0 {
		return value
	}

	seconds, err := strconv.Atoi(raw)
	if err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "node-agent"
	}
	return name
}
