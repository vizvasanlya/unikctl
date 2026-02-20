// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"testing"
	"time"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/internal/controlplaneapi"
)

func TestResumeSLOThreshold_DefaultAndEnvOverride(t *testing.T) {
	t.Setenv("UNIKCTL_RESUME_SLO_MILLIS", "")
	if got := resumeSLOThreshold(); got != 200*time.Millisecond {
		t.Fatalf("unexpected default resume threshold: got=%s want=%s", got, 200*time.Millisecond)
	}

	t.Setenv("UNIKCTL_RESUME_SLO_MILLIS", "350")
	if got := resumeSLOThreshold(); got != 350*time.Millisecond {
		t.Fatalf("unexpected configured resume threshold: got=%s want=%s", got, 350*time.Millisecond)
	}
}

func TestShouldUseRestorePath(t *testing.T) {
	entry := warmPoolEntry{
		SnapshotPath: "/tmp/snapshot.state",
		SnapshotMem:  "/tmp/snapshot.mem",
	}

	if !shouldUseRestorePath(true, entry) {
		t.Fatalf("expected restore path to be selected when snapshots are available")
	}
	if shouldUseRestorePath(false, entry) {
		t.Fatalf("did not expect restore path when snapshot fast-path is disabled")
	}
	if shouldUseRestorePath(true, warmPoolEntry{}) {
		t.Fatalf("did not expect restore path without snapshot metadata")
	}
}

type warmPoolLifecycleService struct {
	machines     map[string]machineapi.Machine
	restoreCalls int
	resumeCalls  int
	startCalls   int
}

func (service *warmPoolLifecycleService) Create(context.Context, *machineapi.Machine) (*machineapi.Machine, error) {
	return &machineapi.Machine{}, nil
}

func (service *warmPoolLifecycleService) Start(_ context.Context, machine *machineapi.Machine) (*machineapi.Machine, error) {
	service.startCalls++
	return machine, nil
}

func (service *warmPoolLifecycleService) Pause(context.Context, *machineapi.Machine) (*machineapi.Machine, error) {
	return &machineapi.Machine{}, nil
}

func (service *warmPoolLifecycleService) Stop(context.Context, *machineapi.Machine) (*machineapi.Machine, error) {
	return &machineapi.Machine{}, nil
}

func (service *warmPoolLifecycleService) Update(context.Context, *machineapi.Machine) (*machineapi.Machine, error) {
	return &machineapi.Machine{}, nil
}

func (service *warmPoolLifecycleService) Delete(context.Context, *machineapi.Machine) (*machineapi.Machine, error) {
	return &machineapi.Machine{}, nil
}

func (service *warmPoolLifecycleService) Get(_ context.Context, machine *machineapi.Machine) (*machineapi.Machine, error) {
	if machine == nil {
		return &machineapi.Machine{}, nil
	}
	if found, ok := service.machines[machine.Name]; ok {
		copy := found
		return &copy, nil
	}
	return machine, nil
}

func (service *warmPoolLifecycleService) List(context.Context, *machineapi.MachineList) (*machineapi.MachineList, error) {
	list := &machineapi.MachineList{}
	for _, machine := range service.machines {
		list.Items = append(list.Items, machine)
	}
	return list, nil
}

func (service *warmPoolLifecycleService) Watch(context.Context, *machineapi.Machine) (chan *machineapi.Machine, chan error, error) {
	return make(chan *machineapi.Machine), make(chan error), nil
}

func (service *warmPoolLifecycleService) Logs(context.Context, *machineapi.Machine) (chan string, chan error, error) {
	return make(chan string), make(chan error), nil
}

func (service *warmPoolLifecycleService) Resume(_ context.Context, machine *machineapi.Machine) (*machineapi.Machine, error) {
	service.resumeCalls++
	return machine, nil
}

func (service *warmPoolLifecycleService) Restore(_ context.Context, machine *machineapi.Machine) (*machineapi.Machine, error) {
	service.restoreCalls++
	return machine, nil
}

func TestWarmSnapshotFastPath_SecondDeployUsesRestore(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "2")

	manager, err := newWarmPoolManager(t.TempDir())
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	request := &controlplaneapi.DeployRequest{
		Runtime:      "ghcr.io/acme/python:latest",
		Platform:     "fc",
		Architecture: "x86_64",
		Tenant:       "tenant-a",
		Args:         []string{"."},
	}

	if err := manager.UpsertPaused(warmPoolEntry{
		ID:           "entry-a",
		Machine:      "pooled-machine-a",
		Runtime:      request.Runtime,
		Platform:     request.Platform,
		Architecture: request.Architecture,
		Tenant:       request.Tenant,
		DeployDigest: warmDeployDigest(request, "first-deploy"),
		SnapshotPath: "/tmp/snapshot.state",
		SnapshotMem:  "/tmp/snapshot.mem",
		SnapshotMeta: "/tmp/snapshot.json",
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert paused warm entry: %v", err)
	}

	service := &warmPoolLifecycleService{
		machines: map[string]machineapi.Machine{},
	}
	pooledMachine := machineapi.Machine{}
	pooledMachine.Name = "pooled-machine-a"
	service.machines["pooled-machine-a"] = pooledMachine

	server := &Server{
		warmPool:         manager,
		snapshotFastPath: true,
		metrics:          newMetricsCollector(),
		machineServiceFactory: func(context.Context) (machineapi.MachineService, error) {
			return service, nil
		},
	}

	selectedMachine, resumed, err := server.tryWarmRestoreOrResume(context.Background(), request, "new-machine-name")
	if err != nil {
		t.Fatalf("warm restore-or-resume: %v", err)
	}
	if !resumed {
		t.Fatalf("expected warm path to be taken")
	}
	if selectedMachine != "pooled-machine-a" {
		t.Fatalf("expected pooled machine selection, got=%q", selectedMachine)
	}
	if service.restoreCalls != 1 {
		t.Fatalf("expected restore to be used once, got=%d", service.restoreCalls)
	}
	if service.resumeCalls != 0 {
		t.Fatalf("did not expect resume fallback when restore succeeds, got=%d", service.resumeCalls)
	}
	if service.startCalls != 0 {
		t.Fatalf("did not expect cold start fallback when restore succeeds, got=%d", service.startCalls)
	}
	if samples := server.metrics.WarmResumeSamples(); samples != 1 {
		t.Fatalf("expected warm resume metrics sample count to be 1, got=%d", samples)
	}

	entry, found, err := manager.GetByMachine("pooled-machine-a")
	if err != nil {
		t.Fatalf("load warm entry state: %v", err)
	}
	if !found {
		t.Fatalf("expected warm entry to remain tracked")
	}
	if entry.State != warmPoolStateRunning {
		t.Fatalf("expected warm entry to transition to running, got=%q", entry.State)
	}
}
