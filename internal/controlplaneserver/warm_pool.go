// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"

	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/walstore"
)

const (
	warmPoolDBDirName          = "warm_pool.db"
	defaultWarmPoolSize        = 0
	defaultWarmPoolIdleTimeout = 5 * time.Minute
	defaultWarmPoolGCThreshold = 30 * time.Minute
	warmPoolStatePaused        = "paused"
	warmPoolStateRunning       = "running"
)

type warmPoolEntry struct {
	ID           string    `json:"id"`
	Machine      string    `json:"machine"`
	Runtime      string    `json:"runtime,omitempty"`
	Platform     string    `json:"platform,omitempty"`
	Architecture string    `json:"architecture,omitempty"`
	Tenant       string    `json:"tenant,omitempty"`
	DeployDigest string    `json:"deploy_digest,omitempty"`
	Node         string    `json:"node,omitempty"`
	State        string    `json:"state"`
	SnapshotPath string    `json:"snapshot_path,omitempty"`
	SnapshotMem  string    `json:"snapshot_mem,omitempty"`
	SnapshotMeta string    `json:"snapshot_meta,omitempty"`
	LastUsedAt   time.Time `json:"last_used_at"`
	LastStateAt  time.Time `json:"last_state_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type warmPoolManager struct {
	backend     *walstore.Store
	targetSize  int
	idleTimeout time.Duration
	gcThreshold time.Duration
}

func newWarmPoolManager(runtimeDir string) (*warmPoolManager, error) {
	backend, err := walstore.Open(filepath.Join(runtimeDir, warmPoolDBDirName))
	if err != nil {
		return nil, err
	}

	targetSize := parseIntEnv("UNIKCTL_WARM_POOL_SIZE", defaultWarmPoolSize)
	idleSeconds := parseIntEnv("UNIKCTL_WARM_POOL_IDLE_TIMEOUT_SECONDS", int(defaultWarmPoolIdleTimeout.Seconds()))
	if idleSeconds <= 0 {
		idleSeconds = int(defaultWarmPoolIdleTimeout.Seconds())
	}

	gcSeconds := parseIntEnv("UNIKCTL_WARM_POOL_GC_SECONDS", int(defaultWarmPoolGCThreshold.Seconds()))
	if gcSeconds <= 0 {
		gcSeconds = int(defaultWarmPoolGCThreshold.Seconds())
	}

	return &warmPoolManager{
		backend:     backend,
		targetSize:  targetSize,
		idleTimeout: time.Duration(idleSeconds) * time.Second,
		gcThreshold: time.Duration(gcSeconds) * time.Second,
	}, nil
}

func (manager *warmPoolManager) Enabled() bool {
	return manager != nil && manager.targetSize > 0
}

func (manager *warmPoolManager) Close() error {
	if manager == nil || manager.backend == nil {
		return nil
	}
	return manager.backend.Close()
}

func (manager *warmPoolManager) TargetSize() int {
	if manager == nil {
		return 0
	}
	return manager.targetSize
}

func (manager *warmPoolManager) IdleTimeout() time.Duration {
	if manager == nil {
		return defaultWarmPoolIdleTimeout
	}
	return manager.idleTimeout
}

func (manager *warmPoolManager) GCThreshold() time.Duration {
	if manager == nil {
		return defaultWarmPoolGCThreshold
	}
	return manager.gcThreshold
}

func (manager *warmPoolManager) UpsertPaused(entry warmPoolEntry) error {
	if manager == nil {
		return nil
	}

	now := time.Now().UTC()
	entry.Machine = strings.TrimSpace(entry.Machine)
	if entry.Machine == "" {
		return fmt.Errorf("warm pool machine is required")
	}

	entry.Runtime = strings.TrimSpace(entry.Runtime)
	entry.Platform = strings.TrimSpace(entry.Platform)
	entry.Architecture = strings.TrimSpace(entry.Architecture)
	entry.Tenant = normalizeTenant(entry.Tenant)
	entry.State = warmPoolStatePaused
	entry.LastUsedAt = now
	entry.LastStateAt = now
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	if strings.TrimSpace(entry.ID) == "" {
		entry.ID = entry.Machine
	}

	return manager.backend.Update(func(txn *badger.Txn) error {
		previousID := ""
		_, _ = walstore.GetJSON(txn, warmPoolMachineKey(entry.Machine), &previousID)
		if previousID != "" && previousID != entry.ID {
			_ = walstore.Delete(txn, warmPoolEntryKey(previousID))
		}

		if err := walstore.SetJSON(txn, warmPoolEntryKey(entry.ID), entry); err != nil {
			return err
		}
		if err := walstore.SetJSON(txn, warmPoolMachineKey(entry.Machine), entry.ID); err != nil {
			return err
		}

		return manager.trimRuntimeTxn(txn, entry.Runtime, manager.targetSize)
	})
}

func (manager *warmPoolManager) AcquireForDeploy(request *controlplaneapi.DeployRequest, machineName string) (warmPoolEntry, bool, error) {
	if manager == nil || !manager.Enabled() {
		return warmPoolEntry{}, false, nil
	}

	now := time.Now().UTC()
	targetDigest := warmDeployDigest(request, "")
	targetTenant := normalizeTenant(firstNonEmpty(request.Tenant, "default"))
	targetRuntime := strings.TrimSpace(request.Runtime)
	targetPlatform := strings.TrimSpace(request.Platform)
	targetArch := strings.TrimSpace(request.Architecture)

	selected := warmPoolEntry{}
	selectedFound := false

	err := manager.backend.Update(func(txn *badger.Txn) error {
		entries, err := manager.listTxn(txn)
		if err != nil {
			return err
		}

		candidates := make([]warmPoolEntry, 0, len(entries))
		for _, entry := range entries {
			if entry.State != warmPoolStatePaused {
				continue
			}
			if entry.DeployDigest != targetDigest {
				continue
			}
			if normalizeTenant(entry.Tenant) != targetTenant {
				continue
			}
			if strings.TrimSpace(targetRuntime) != "" && strings.TrimSpace(entry.Runtime) != strings.TrimSpace(targetRuntime) {
				continue
			}
			if strings.TrimSpace(targetPlatform) != "" && strings.TrimSpace(entry.Platform) != strings.TrimSpace(targetPlatform) {
				continue
			}
			if strings.TrimSpace(targetArch) != "" && strings.TrimSpace(entry.Architecture) != strings.TrimSpace(targetArch) {
				continue
			}

			candidates = append(candidates, entry)
		}

		if len(candidates) == 0 {
			return nil
		}

		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].LastUsedAt.Equal(candidates[j].LastUsedAt) {
				return candidates[i].ID < candidates[j].ID
			}
			return candidates[i].LastUsedAt.Before(candidates[j].LastUsedAt)
		})

		selected = candidates[0]
		selectedFound = true
		selected.State = warmPoolStateRunning
		selected.LastUsedAt = now
		selected.LastStateAt = now

		return walstore.SetJSON(txn, warmPoolEntryKey(selected.ID), selected)
	})
	if err != nil {
		return warmPoolEntry{}, false, err
	}

	return selected, selectedFound, nil
}

func (manager *warmPoolManager) MarkRunning(machineName string) error {
	if manager == nil {
		return nil
	}

	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return nil
	}

	return manager.backend.Update(func(txn *badger.Txn) error {
		entryID := ""
		found, err := walstore.GetJSON(txn, warmPoolMachineKey(machineName), &entryID)
		if err != nil || !found || strings.TrimSpace(entryID) == "" {
			return err
		}

		entry := warmPoolEntry{}
		found, err = walstore.GetJSON(txn, warmPoolEntryKey(entryID), &entry)
		if err != nil || !found {
			return err
		}

		entry.State = warmPoolStateRunning
		entry.LastStateAt = time.Now().UTC()
		entry.LastUsedAt = entry.LastStateAt
		return walstore.SetJSON(txn, warmPoolEntryKey(entry.ID), entry)
	})
}

func (manager *warmPoolManager) GetByMachine(machine string) (warmPoolEntry, bool, error) {
	if manager == nil {
		return warmPoolEntry{}, false, nil
	}

	entry := warmPoolEntry{}
	found := false
	err := manager.backend.View(func(txn *badger.Txn) error {
		entryID := ""
		ok, err := walstore.GetJSON(txn, warmPoolMachineKey(strings.TrimSpace(machine)), &entryID)
		if err != nil || !ok || strings.TrimSpace(entryID) == "" {
			return err
		}
		ok, err = walstore.GetJSON(txn, warmPoolEntryKey(entryID), &entry)
		if err != nil {
			return err
		}
		found = ok
		return nil
	})
	if err != nil {
		return warmPoolEntry{}, false, err
	}
	return entry, found, nil
}

func (manager *warmPoolManager) List() ([]warmPoolEntry, error) {
	if manager == nil {
		return []warmPoolEntry{}, nil
	}

	entries := []warmPoolEntry{}
	err := manager.backend.View(func(txn *badger.Txn) error {
		list, err := manager.listTxn(txn)
		if err != nil {
			return err
		}
		entries = list
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Runtime == entries[j].Runtime {
			return entries[i].Machine < entries[j].Machine
		}
		return entries[i].Runtime < entries[j].Runtime
	})
	return entries, nil
}

func (manager *warmPoolManager) GarbageCollect() (int, error) {
	if manager == nil {
		return 0, nil
	}

	now := time.Now().UTC()
	removed := 0
	err := manager.backend.Update(func(txn *badger.Txn) error {
		entries, err := manager.listTxn(txn)
		if err != nil {
			return err
		}

		referenced := map[string]int{}
		for _, entry := range entries {
			if strings.TrimSpace(entry.SnapshotPath) != "" {
				referenced[entry.SnapshotPath]++
			}
			if strings.TrimSpace(entry.SnapshotMem) != "" {
				referenced[entry.SnapshotMem]++
			}
			if strings.TrimSpace(entry.SnapshotMeta) != "" {
				referenced[entry.SnapshotMeta]++
			}
		}

		for _, entry := range entries {
			if entry.State != warmPoolStatePaused {
				continue
			}
			if now.Sub(entry.LastUsedAt) < manager.gcThreshold {
				continue
			}

			_ = walstore.Delete(txn, warmPoolEntryKey(entry.ID))
			_ = walstore.Delete(txn, warmPoolMachineKey(entry.Machine))
			removed++

			for _, candidate := range []string{entry.SnapshotPath, entry.SnapshotMem, entry.SnapshotMeta} {
				path := strings.TrimSpace(candidate)
				if path == "" {
					continue
				}
				referenced[path]--
				if referenced[path] <= 0 {
					_ = os.Remove(path)
				}
			}
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return removed, nil
}

func (manager *warmPoolManager) listTxn(txn *badger.Txn) ([]warmPoolEntry, error) {
	entries := []warmPoolEntry{}
	iterator := txn.NewIterator(badger.IteratorOptions{
		PrefetchValues: true,
		PrefetchSize:   30,
	})
	defer iterator.Close()

	prefix := []byte("warm/entry/")
	for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
		item := iterator.Item()
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return nil, err
		}

		entry := warmPoolEntry{}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (manager *warmPoolManager) trimRuntimeTxn(txn *badger.Txn, runtime string, keep int) error {
	if keep <= 0 {
		return nil
	}

	runtime = strings.TrimSpace(runtime)
	entries, err := manager.listTxn(txn)
	if err != nil {
		return err
	}

	paused := make([]warmPoolEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Runtime) != runtime {
			continue
		}
		if entry.State != warmPoolStatePaused {
			continue
		}
		paused = append(paused, entry)
	}

	if len(paused) <= keep {
		return nil
	}

	sort.SliceStable(paused, func(i, j int) bool {
		if paused[i].LastUsedAt.Equal(paused[j].LastUsedAt) {
			return paused[i].ID < paused[j].ID
		}
		return paused[i].LastUsedAt.Before(paused[j].LastUsedAt)
	})

	for _, stale := range paused[:len(paused)-keep] {
		_ = walstore.Delete(txn, warmPoolEntryKey(stale.ID))
		_ = walstore.Delete(txn, warmPoolMachineKey(stale.Machine))
	}

	return nil
}

func warmPoolEntryKey(id string) string {
	return "warm/entry/" + strings.TrimSpace(id)
}

func warmPoolMachineKey(machine string) string {
	return "warm/machine/" + strings.TrimSpace(machine)
}

func warmDeployDigest(request *controlplaneapi.DeployRequest, machineName string) string {
	parts := []string{}
	if request != nil {
		parts = append(parts,
			strings.TrimSpace(request.Runtime),
			strings.TrimSpace(request.Rootfs),
			strings.TrimSpace(request.Target),
			strings.TrimSpace(request.Platform),
			strings.TrimSpace(request.Architecture),
			strings.Join(request.Args, "\x00"),
		)
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:16])
}

func parseIntEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}
