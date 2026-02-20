// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"

	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/walstore"
)

const workloadStoreDirName = "workloads.db"

type workloadRecord struct {
	Machine            string                        `json:"machine"`
	Node               string                        `json:"node"`
	Tenant             string                        `json:"tenant,omitempty"`
	RequestedCPUMilli  int64                         `json:"requested_cpu_milli,omitempty"`
	RequestedMemBytes  int64                         `json:"requested_mem_bytes,omitempty"`
	Request            controlplaneapi.DeployRequest `json:"request"`
	CreatedAt          time.Time                     `json:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
	ActualRSSBytes     int64                         `json:"actual_rss_bytes,omitempty"`
	HostOverheadBytes  int64                         `json:"host_overhead_bytes,omitempty"`
	RestartCount       int64                         `json:"restart_count,omitempty"`
	StealTimeMillis    int64                         `json:"steal_time_millis,omitempty"`
	MemoryPressurePct  float64                       `json:"memory_pressure_pct,omitempty"`
	NoisyNeighborScore float64                       `json:"noisy_neighbor_score,omitempty"`
}

type driverOverheadRecord struct {
	Driver    string    `json:"driver"`
	Samples   int64     `json:"samples"`
	AvgBytes  int64     `json:"avg_bytes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type workloadStore struct {
	backend *walstore.Store
}

func newWorkloadStore(ctx context.Context) (*workloadStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	backend, err := walstore.Open(filepath.Join(runtimeDir, workloadStoreDirName))
	if err != nil {
		return nil, err
	}

	return &workloadStore{backend: backend}, nil
}

func (store *workloadStore) Upsert(machineName, nodeName string, request controlplaneapi.DeployRequest) error {
	now := time.Now().UTC()
	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return fmt.Errorf("machine name is required")
	}

	return store.backend.Update(func(txn *badger.Txn) error {
		existing, found, err := store.getTxn(txn, machineName)
		if err != nil {
			return err
		}
		if found {
			_ = walstore.Delete(txn, workloadNodeKey(existing.Node, existing.Machine))
			_ = walstore.Delete(txn, workloadTenantKey(existing.Tenant, existing.Machine))
		}

		record := workloadRecord{
			Machine:           machineName,
			Node:              strings.TrimSpace(nodeName),
			Tenant:            normalizeTenant(request.Tenant),
			RequestedCPUMilli: requestedCPUMilli(&request),
			RequestedMemBytes: requestedMemoryBytes(&request),
			Request:           sanitizeDeployRequest(request),
			CreatedAt:         now,
			UpdatedAt:         now,
			HostOverheadBytes: estimateHostOverheadBytes(&request),
		}
		if found {
			record.CreatedAt = existing.CreatedAt
			record.ActualRSSBytes = existing.ActualRSSBytes
			record.RestartCount = existing.RestartCount
			record.StealTimeMillis = existing.StealTimeMillis
			record.MemoryPressurePct = existing.MemoryPressurePct
			record.NoisyNeighborScore = existing.NoisyNeighborScore
		}

		if err := store.setTxn(txn, record); err != nil {
			return err
		}

		if err := walstore.SetJSON(txn, workloadNodeKey(record.Node, record.Machine), true); err != nil {
			return err
		}
		return walstore.SetJSON(txn, workloadTenantKey(record.Tenant, record.Machine), true)
	})
}

func (store *workloadStore) RemoveMachines(names ...string) error {
	if len(names) == 0 {
		return nil
	}

	targets := map[string]struct{}{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		targets[name] = struct{}{}
	}

	return store.backend.Update(func(txn *badger.Txn) error {
		for machine := range targets {
			record, found, err := store.getTxn(txn, machine)
			if err != nil {
				return err
			}
			if !found {
				continue
			}

			_ = walstore.Delete(txn, workloadNodeKey(record.Node, record.Machine))
			_ = walstore.Delete(txn, workloadTenantKey(record.Tenant, record.Machine))
			if err := walstore.Delete(txn, workloadKey(machine)); err != nil && err != badger.ErrKeyNotFound {
				return err
			}
		}
		return nil
	})
}

func (store *workloadStore) Clear() error {
	return store.backend.Update(func(txn *badger.Txn) error {
		records, err := store.listTxn(txn)
		if err != nil {
			return err
		}
		for _, record := range records {
			_ = walstore.Delete(txn, workloadNodeKey(record.Node, record.Machine))
			_ = walstore.Delete(txn, workloadTenantKey(record.Tenant, record.Machine))
			_ = walstore.Delete(txn, workloadKey(record.Machine))
		}
		return nil
	})
}

func (store *workloadStore) Get(machineName string) (workloadRecord, bool, error) {
	record := workloadRecord{}
	found := false
	err := store.backend.View(func(txn *badger.Txn) error {
		var getErr error
		record, found, getErr = store.getTxn(txn, strings.TrimSpace(machineName))
		return getErr
	})
	if err != nil {
		return workloadRecord{}, false, err
	}

	return record, found, nil
}

func (store *workloadStore) List() ([]workloadRecord, error) {
	records := []workloadRecord{}
	err := store.backend.View(func(txn *badger.Txn) error {
		list, listErr := store.listTxn(txn)
		if listErr != nil {
			return listErr
		}
		records = list
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading workload store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Machine < records[j].Machine
	})
	return records, nil
}

func (store *workloadStore) ByNode(nodeName string) ([]workloadRecord, error) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return []workloadRecord{}, nil
	}

	return store.byIndexedPrefix("workload-node/" + nodeName + "/")
}

func (store *workloadStore) ByTenant(tenant string) ([]workloadRecord, error) {
	return store.byIndexedPrefix("workload-tenant/" + normalizeTenant(tenant) + "/")
}

func (store *workloadStore) IncrementRestart(machine string) error {
	machine = strings.TrimSpace(machine)
	if machine == "" {
		return nil
	}

	return store.backend.Update(func(txn *badger.Txn) error {
		record, found, err := store.getTxn(txn, machine)
		if err != nil || !found {
			return err
		}

		record.RestartCount++
		record.UpdatedAt = time.Now().UTC()
		record.NoisyNeighborScore = computeNoisyNeighborScore(record.RestartCount, record.StealTimeMillis, record.MemoryPressurePct)
		return store.setTxn(txn, record)
	})
}

func (store *workloadStore) UpdateRuntimeStats(machine string, actualRSSBytes, stealTimeMillis int64, memoryPressurePct float64) error {
	machine = strings.TrimSpace(machine)
	if machine == "" {
		return nil
	}

	return store.backend.Update(func(txn *badger.Txn) error {
		record, found, err := store.getTxn(txn, machine)
		if err != nil || !found {
			return err
		}

		record.ActualRSSBytes = maxInt64(actualRSSBytes, 0)
		record.StealTimeMillis = maxInt64(stealTimeMillis, 0)
		record.MemoryPressurePct = clampFloat(memoryPressurePct, 0, 1)
		record.HostOverheadBytes = store.calculateHostOverheadTxn(txn, record)
		record.NoisyNeighborScore = computeNoisyNeighborScore(record.RestartCount, record.StealTimeMillis, record.MemoryPressurePct)
		record.UpdatedAt = time.Now().UTC()
		return store.setTxn(txn, record)
	})
}

func (store *workloadStore) DriverOverheadAverages() (map[string]int64, error) {
	averages := map[string]int64{}
	err := store.backend.View(func(txn *badger.Txn) error {
		iterator := txn.NewIterator(badger.IteratorOptions{
			PrefetchValues: true,
			PrefetchSize:   20,
		})
		defer iterator.Close()

		prefix := []byte("driver-overhead/")
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			item := iterator.Item()
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			record := driverOverheadRecord{}
			if err := json.Unmarshal(raw, &record); err != nil {
				return err
			}
			driver := normalizeDriverName(record.Driver)
			if driver == "" || record.AvgBytes <= 0 {
				continue
			}
			averages[driver] = record.AvgBytes
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return averages, nil
}

func (store *workloadStore) byIndexedPrefix(prefix string) ([]workloadRecord, error) {
	records := []workloadRecord{}
	err := store.backend.View(func(txn *badger.Txn) error {
		iterator := txn.NewIterator(badger.IteratorOptions{
			PrefetchValues: true,
			PrefetchSize:   30,
		})
		defer iterator.Close()

		prefixBytes := []byte(prefix)
		for iterator.Seek(prefixBytes); iterator.ValidForPrefix(prefixBytes); iterator.Next() {
			item := iterator.Item()
			key := string(item.Key())
			parts := strings.Split(key, "/")
			if len(parts) < 3 {
				continue
			}
			machine := strings.TrimSpace(parts[len(parts)-1])
			if machine == "" {
				continue
			}

			record, found, err := store.getTxn(txn, machine)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			records = append(records, record)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Machine < records[j].Machine
	})
	return records, nil
}

func (store *workloadStore) getTxn(txn *badger.Txn, machineName string) (workloadRecord, bool, error) {
	record := workloadRecord{}
	found, err := walstore.GetJSON(txn, workloadKey(machineName), &record)
	return record, found, err
}

func (store *workloadStore) setTxn(txn *badger.Txn, record workloadRecord) error {
	return walstore.SetJSON(txn, workloadKey(record.Machine), record)
}

func (store *workloadStore) listTxn(txn *badger.Txn) ([]workloadRecord, error) {
	records := []workloadRecord{}
	iterator := txn.NewIterator(badger.IteratorOptions{
		PrefetchValues: true,
		PrefetchSize:   50,
	})
	defer iterator.Close()

	prefix := []byte("workload/")
	for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
		item := iterator.Item()
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return nil, err
		}

		record := workloadRecord{}
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func workloadKey(machine string) string {
	return "workload/" + strings.TrimSpace(machine)
}

func workloadNodeKey(node, machine string) string {
	return "workload-node/" + strings.TrimSpace(node) + "/" + strings.TrimSpace(machine)
}

func workloadTenantKey(tenant, machine string) string {
	return "workload-tenant/" + normalizeTenant(tenant) + "/" + strings.TrimSpace(machine)
}

func driverOverheadKey(driver string) string {
	return "driver-overhead/" + normalizeDriverName(driver)
}

func sanitizeDeployRequest(request controlplaneapi.DeployRequest) controlplaneapi.DeployRequest {
	request.ArtifactID = ""
	request.ArtifactPath = ""
	request.RootfsArtifactID = ""
	request.RootfsArtifactPath = ""
	request.IdempotencyKey = ""
	request.TraceID = ""
	return request
}

func estimateHostOverheadBytes(request *controlplaneapi.DeployRequest) int64 {
	_ = request
	// Driver overhead starts at zero and converges from observed runtime samples.
	return 0
}

func (store *workloadStore) calculateHostOverheadTxn(txn *badger.Txn, record workloadRecord) int64 {
	driver := normalizeDriverName(firstNonEmpty(record.Request.Platform, record.Request.Runtime))
	if driver == "" {
		driver = "unknown"
	}

	sample := int64(0)
	if record.ActualRSSBytes > 0 && record.RequestedMemBytes > 0 {
		sample = record.ActualRSSBytes - record.RequestedMemBytes
		if sample < 0 {
			sample = 0
		}
	}

	overheadRecord := driverOverheadRecord{}
	found, _ := walstore.GetJSON(txn, driverOverheadKey(driver), &overheadRecord)
	if !found {
		overheadRecord = driverOverheadRecord{
			Driver: driver,
		}
	}

	if sample > 0 {
		if overheadRecord.Samples <= 0 || overheadRecord.AvgBytes <= 0 {
			overheadRecord.AvgBytes = sample
			overheadRecord.Samples = 1
		} else {
			nextSamples := overheadRecord.Samples + 1
			overheadRecord.AvgBytes = ((overheadRecord.AvgBytes * overheadRecord.Samples) + sample) / nextSamples
			overheadRecord.Samples = nextSamples
		}
		overheadRecord.UpdatedAt = time.Now().UTC()
		_ = walstore.SetJSON(txn, driverOverheadKey(driver), overheadRecord)
	}

	if overheadRecord.AvgBytes > 0 {
		return overheadRecord.AvgBytes
	}
	if sample > 0 {
		return sample
	}

	return estimateHostOverheadBytes(&record.Request)
}

func normalizeDriverName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "firecracker", "fc":
		return "fc"
	case "qemu", "kvm":
		return "qemu"
	case "xen":
		return "xen"
	default:
		return value
	}
}

func computeNoisyNeighborScore(restartCount int64, stealTimeMillis int64, memoryPressurePct float64) float64 {
	restartFactor := float64(restartCount) * 0.25
	stealFactor := float64(stealTimeMillis) / 1000.0
	pressureFactor := clampFloat(memoryPressurePct, 0, 1)
	return restartFactor + stealFactor + pressureFactor
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
