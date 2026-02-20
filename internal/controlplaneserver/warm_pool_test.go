// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"

	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/walstore"
)

func TestWarmPoolAcquireForDeploy(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "2")
	t.Setenv("UNIKCTL_WARM_POOL_IDLE_TIMEOUT_SECONDS", "60")
	t.Setenv("UNIKCTL_WARM_POOL_GC_SECONDS", "120")

	temp := t.TempDir()
	manager, err := newWarmPoolManager(temp)
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	request := &controlplaneapi.DeployRequest{
		Runtime:      "ghcr.io/acme/base:latest",
		Platform:     "fc",
		Architecture: "x86_64",
		Tenant:       "default",
		Args:         []string{"."},
	}

	if err := manager.UpsertPaused(warmPoolEntry{
		Machine:      "app-a",
		Runtime:      request.Runtime,
		Platform:     request.Platform,
		Architecture: request.Architecture,
		Tenant:       request.Tenant,
		DeployDigest: warmDeployDigest(request, "app-a"),
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert paused entry: %v", err)
	}

	entry, found, err := manager.AcquireForDeploy(request, "app-a")
	if err != nil {
		t.Fatalf("acquire warm entry: %v", err)
	}
	if !found {
		t.Fatalf("expected warm entry to be found")
	}
	if entry.Machine != "app-a" {
		t.Fatalf("unexpected machine: got=%q", entry.Machine)
	}
	if entry.State != warmPoolStateRunning {
		t.Fatalf("expected acquired entry to transition to running, got=%q", entry.State)
	}
}

func TestWarmPoolAcquireForDeploy_RuntimeBasedAcrossMachineNames(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "2")
	temp := t.TempDir()

	manager, err := newWarmPoolManager(temp)
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	request := &controlplaneapi.DeployRequest{
		Runtime:      "ghcr.io/acme/base:latest",
		Platform:     "fc",
		Architecture: "x86_64",
		Tenant:       "default",
		Args:         []string{"."},
	}

	if err := manager.UpsertPaused(warmPoolEntry{
		Machine:      "pooled-machine-a",
		Runtime:      request.Runtime,
		Platform:     request.Platform,
		Architecture: request.Architecture,
		Tenant:       request.Tenant,
		DeployDigest: warmDeployDigest(request, "ignored-machine-name"),
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert paused entry: %v", err)
	}

	entry, found, err := manager.AcquireForDeploy(request, "new-machine-name")
	if err != nil {
		t.Fatalf("acquire warm entry: %v", err)
	}
	if !found {
		t.Fatalf("expected warm entry to be found across machine names")
	}
	if entry.Machine != "pooled-machine-a" {
		t.Fatalf("expected pooled machine to be returned, got=%q", entry.Machine)
	}
}

func TestWarmDeployDigest_IgnoresMachineNameForRuntimeMatching(t *testing.T) {
	request := &controlplaneapi.DeployRequest{
		Runtime:      "ghcr.io/acme/base:latest",
		Platform:     "fc",
		Architecture: "x86_64",
		Tenant:       "default",
		Args:         []string{"./app"},
	}

	first := warmDeployDigest(request, "machine-a")
	second := warmDeployDigest(request, "machine-b")
	if first != second {
		t.Fatalf("expected runtime digest to be machine-name agnostic: %q != %q", first, second)
	}
}

func TestWarmPoolAcquireMissForDifferentDigest(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "2")
	temp := t.TempDir()

	manager, err := newWarmPoolManager(temp)
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	source := &controlplaneapi.DeployRequest{
		Runtime:      "ghcr.io/acme/base:latest",
		Platform:     "fc",
		Architecture: "x86_64",
		Args:         []string{"./a"},
	}

	if err := manager.UpsertPaused(warmPoolEntry{
		Machine:      "app-a",
		Runtime:      source.Runtime,
		Platform:     source.Platform,
		Architecture: source.Architecture,
		Tenant:       "default",
		DeployDigest: warmDeployDigest(source, "app-a"),
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert paused entry: %v", err)
	}

	target := &controlplaneapi.DeployRequest{
		Runtime:      source.Runtime,
		Platform:     source.Platform,
		Architecture: source.Architecture,
		Args:         []string{"./b"},
	}

	_, found, err := manager.AcquireForDeploy(target, "app-a")
	if err != nil {
		t.Fatalf("acquire warm entry: %v", err)
	}
	if found {
		t.Fatalf("expected no warm entry when deploy digest changes")
	}
}

func TestWarmPoolGarbageCollectRemovesStaleSnapshots(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "2")
	t.Setenv("UNIKCTL_WARM_POOL_GC_SECONDS", "1")

	temp := t.TempDir()
	manager, err := newWarmPoolManager(temp)
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	snapshotState := filepath.Join(temp, "snapshot.state")
	snapshotMem := filepath.Join(temp, "snapshot.mem")
	snapshotMeta := filepath.Join(temp, "snapshot.json")
	for _, path := range []string{snapshotState, snapshotMem, snapshotMeta} {
		if err := os.WriteFile(path, []byte("snapshot"), 0o644); err != nil {
			t.Fatalf("create snapshot artifact: %v", err)
		}
	}

	if err := manager.UpsertPaused(warmPoolEntry{
		ID:           "entry-a",
		Machine:      "app-a",
		Runtime:      "ghcr.io/acme/base:latest",
		DeployDigest: "digest-a",
		SnapshotPath: snapshotState,
		SnapshotMem:  snapshotMem,
		SnapshotMeta: snapshotMeta,
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert paused entry: %v", err)
	}

	err = manager.backend.Update(func(txn *badger.Txn) error {
		entry := warmPoolEntry{}
		ok, err := walstore.GetJSON(txn, warmPoolEntryKey("entry-a"), &entry)
		if err != nil || !ok {
			return err
		}
		entry.LastUsedAt = time.Now().UTC().Add(-2 * time.Minute)
		entry.LastStateAt = entry.LastUsedAt
		return walstore.SetJSON(txn, warmPoolEntryKey("entry-a"), entry)
	})
	if err != nil {
		t.Fatalf("backdate warm pool entry: %v", err)
	}

	removed, err := manager.GarbageCollect()
	if err != nil {
		t.Fatalf("garbage collect: %v", err)
	}
	if removed != 1 {
		t.Fatalf("unexpected removed count: got=%d want=%d", removed, 1)
	}

	for _, path := range []string{snapshotState, snapshotMem, snapshotMeta} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected snapshot file to be removed: %s", path)
		}
	}
}

func TestWarmPoolTrimRuntimeToTargetSize(t *testing.T) {
	t.Setenv("UNIKCTL_WARM_POOL_SIZE", "1")
	temp := t.TempDir()

	manager, err := newWarmPoolManager(temp)
	if err != nil {
		t.Fatalf("new warm pool manager: %v", err)
	}
	defer manager.Close()

	if err := manager.UpsertPaused(warmPoolEntry{
		ID:           "entry-a",
		Machine:      "app-a",
		Runtime:      "ghcr.io/acme/base:latest",
		DeployDigest: "digest-a",
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert first entry: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	if err := manager.UpsertPaused(warmPoolEntry{
		ID:           "entry-b",
		Machine:      "app-b",
		Runtime:      "ghcr.io/acme/base:latest",
		DeployDigest: "digest-b",
		State:        warmPoolStatePaused,
	}); err != nil {
		t.Fatalf("upsert second entry: %v", err)
	}

	entries, err := manager.List()
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected trim to keep one paused entry, got=%d", len(entries))
	}
	if entries[0].ID != "entry-b" {
		t.Fatalf("expected newest entry to remain, got=%s", entries[0].ID)
	}
}
