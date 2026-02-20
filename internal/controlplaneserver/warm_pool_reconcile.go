// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/log"
	"unikctl.sh/machine/lifecycle"
)

const warmPoolReconcileInterval = 30 * time.Second

func (server *Server) reconcileWarmPool(ctx context.Context) {
	server.reconcileWarmPoolOnce(ctx)

	ticker := time.NewTicker(warmPoolReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.reconcileWarmPoolOnce(ctx)
		}
	}
}

func (server *Server) reconcileWarmPoolOnce(ctx context.Context) {
	if server.warmPool == nil || !server.warmPool.Enabled() {
		return
	}

	records, err := server.workloads.List()
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not read workloads for warm pool reconcile")
		return
	}
	if len(records) == 0 {
		return
	}

	localMachines, err := listMachines(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not list local machines for warm pool reconcile")
		return
	}
	localStates := map[string]machineStatus{}
	for _, machine := range localMachines {
		localStates[machine.Name] = machine
	}

	now := time.Now().UTC()
	for _, record := range records {
		if strings.TrimSpace(record.Machine) == "" {
			continue
		}
		if strings.TrimSpace(record.Node) != "" && strings.TrimSpace(record.Node) != hostname() {
			continue
		}

		machine, ok := localStates[record.Machine]
		if !ok {
			continue
		}
		if machine.State.String() != "running" {
			continue
		}

		idleFor := now.Sub(record.UpdatedAt)
		if idleFor < server.warmPool.IdleTimeout() {
			continue
		}

		existing, found, err := server.warmPool.GetByMachine(record.Machine)
		if err == nil && found && existing.State == warmPoolStatePaused {
			continue
		}

		entry, err := server.pauseAndSnapshotForWarmPool(ctx, record)
		if err != nil {
			log.G(ctx).WithError(err).WithField("machine", record.Machine).Debug("could not pause/snapshot machine for warm pool")
			continue
		}

		if err := server.warmPool.UpsertPaused(entry); err != nil {
			log.G(ctx).WithError(err).WithField("machine", record.Machine).Warn("could not upsert warm pool entry")
			continue
		}

		log.G(ctx).WithField("machine", record.Machine).Info("machine paused and snapshotted into warm pool")
	}

	if removed, err := server.warmPool.GarbageCollect(); err != nil {
		log.G(ctx).WithError(err).Debug("warm pool snapshot garbage collection failed")
	} else if removed > 0 {
		server.metrics.IncrementWarmGC(removed)
		log.G(ctx).WithField("removed", removed).Info("warm pool snapshot garbage collection completed")
	}
}

func (server *Server) pauseAndSnapshotForWarmPool(ctx context.Context, record workloadRecord) (warmPoolEntry, error) {
	controller, err := server.machineService(ctx)
	if err != nil {
		return warmPoolEntry{}, err
	}

	machine, err := findMachine(ctx, controller, record.Machine)
	if err != nil {
		return warmPoolEntry{}, err
	}

	lifecycleDriver := lifecycle.Adapt(controller)

	snapshotStarted := time.Now().UTC()
	machine, err = lifecycleDriver.Snapshot(ctx, machine)
	if err != nil && !errors.Is(err, lifecycle.ErrUnsupported) {
		return warmPoolEntry{}, err
	}
	if err == nil {
		server.metrics.RecordSnapshotLatency(time.Since(snapshotStarted))
	}

	pauseStarted := time.Now().UTC()
	machine, err = lifecycleDriver.Pause(ctx, machine)
	if err != nil {
		return warmPoolEntry{}, err
	}
	server.metrics.RecordWarmPauseLatency(time.Since(pauseStarted))

	entry := warmPoolEntry{
		ID:           machine.Name,
		Machine:      machine.Name,
		Runtime:      strings.TrimSpace(record.Request.Runtime),
		Platform:     strings.TrimSpace(record.Request.Platform),
		Architecture: strings.TrimSpace(record.Request.Architecture),
		Tenant:       normalizeTenant(record.Request.Tenant),
		DeployDigest: warmDeployDigest(&record.Request, machine.Name),
		Node:         hostname(),
		State:        warmPoolStatePaused,
	}

	entry.SnapshotPath, entry.SnapshotMem, entry.SnapshotMeta = snapshotPathsFromPlatformConfig(machine.Status.PlatformConfig)

	return entry, nil
}

func (server *Server) tryWarmRestoreOrResume(ctx context.Context, request *controlplaneapi.DeployRequest, machineName string) (string, bool, error) {
	if server.warmPool == nil || !server.warmPool.Enabled() {
		return "", false, nil
	}

	entry, found, err := server.warmPool.AcquireForDeploy(request, machineName)
	if err != nil || !found {
		return "", false, err
	}

	controller, err := server.machineService(ctx)
	if err != nil {
		return "", false, err
	}

	machine, err := findMachine(ctx, controller, entry.Machine)
	if err != nil {
		return "", false, err
	}

	lifecycleDriver := lifecycle.Adapt(controller)
	resumeStarted := time.Now().UTC()

	usedRestore := false
	if shouldUseRestorePath(server.snapshotFastPath, entry) {
		if _, err := lifecycleDriver.Restore(ctx, machine); err == nil {
			usedRestore = true
		} else if !errors.Is(err, lifecycle.ErrUnsupported) {
			return "", false, err
		}
	}

	if !usedRestore {
		_, err = lifecycleDriver.Resume(ctx, machine)
		if err != nil && !errors.Is(err, lifecycle.ErrUnsupported) {
			return "", false, err
		}
		if errors.Is(err, lifecycle.ErrUnsupported) {
			if _, err := lifecycleDriver.Start(ctx, machine); err != nil {
				return "", false, err
			}
		}
	}

	latency := time.Since(resumeStarted)
	server.metrics.RecordWarmResumeLatency(latency)
	if threshold := resumeSLOThreshold(); threshold > 0 && latency > threshold {
		server.metrics.IncrementResumeSLOViolation()
		log.G(ctx).WithFields(map[string]interface{}{
			"machine":   machine.Name,
			"latency":   latency.String(),
			"threshold": threshold.String(),
			"path":      firstNonEmpty(map[bool]string{true: "restore", false: "resume"}[usedRestore], "resume"),
		}).Warn("warm start latency exceeded configured resume threshold")
	}

	if err := server.warmPool.MarkRunning(entry.Machine); err != nil {
		log.G(ctx).WithError(err).WithField("machine", entry.Machine).Debug("could not update warm pool running state")
	}

	return entry.Machine, true, nil
}

func resumeSLOThreshold() time.Duration {
	raw := strings.TrimSpace(os.Getenv("UNIKCTL_RESUME_SLO_MILLIS"))
	if raw == "" {
		return 200 * time.Millisecond
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 200 * time.Millisecond
	}

	return time.Duration(parsed) * time.Millisecond
}

func shouldUseRestorePath(snapshotFastPath bool, entry warmPoolEntry) bool {
	if !snapshotFastPath {
		return false
	}
	return strings.TrimSpace(entry.SnapshotPath) != "" && strings.TrimSpace(entry.SnapshotMem) != ""
}

func snapshotPathsFromPlatformConfig(config any) (string, string, string) {
	if config == nil {
		return "", "", ""
	}

	lookup := func(values map[string]any, keys ...string) string {
		for _, key := range keys {
			raw, ok := values[key]
			if !ok {
				continue
			}
			text, _ := raw.(string)
			text = strings.TrimSpace(text)
			if text != "" {
				return text
			}
		}
		return ""
	}

	switch typed := config.(type) {
	case map[string]any:
		return lookup(typed, "snapshotPath", "snapshot_path"),
			lookup(typed, "snapshotMem", "snapshot_mem"),
			lookup(typed, "snapshotMeta", "snapshot_meta")
	}

	raw, err := json.Marshal(config)
	if err != nil {
		return "", "", ""
	}

	parsed := map[string]any{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", ""
	}

	return lookup(parsed, "snapshotPath", "snapshot_path"),
		lookup(parsed, "snapshotMem", "snapshot_mem"),
		lookup(parsed, "snapshotMeta", "snapshot_meta")
}
