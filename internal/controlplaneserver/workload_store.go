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

	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/lockedfile"
)

const workloadStoreFileName = "workloads.json"

type workloadRecord struct {
	Machine   string                        `json:"machine"`
	Node      string                        `json:"node"`
	Request   controlplaneapi.DeployRequest `json:"request"`
	CreatedAt time.Time                     `json:"created_at"`
	UpdatedAt time.Time                     `json:"updated_at"`
}

type workloadStore struct {
	path string
}

func newWorkloadStore(ctx context.Context) (*workloadStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	return &workloadStore{
		path: filepath.Join(runtimeDir, workloadStoreFileName),
	}, nil
}

func (store *workloadStore) Upsert(machineName, nodeName string, request controlplaneapi.DeployRequest) error {
	now := time.Now().UTC()
	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return fmt.Errorf("machine name is required")
	}

	return store.transform(func(records []workloadRecord) ([]workloadRecord, error) {
		for i := range records {
			if records[i].Machine != machineName {
				continue
			}

			records[i].Node = strings.TrimSpace(nodeName)
			records[i].Request = sanitizeDeployRequest(request)
			records[i].UpdatedAt = now
			return records, nil
		}

		records = append(records, workloadRecord{
			Machine:   machineName,
			Node:      strings.TrimSpace(nodeName),
			Request:   sanitizeDeployRequest(request),
			CreatedAt: now,
			UpdatedAt: now,
		})
		return records, nil
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

	return store.transform(func(records []workloadRecord) ([]workloadRecord, error) {
		filtered := make([]workloadRecord, 0, len(records))
		for _, record := range records {
			if _, ok := targets[record.Machine]; ok {
				continue
			}
			filtered = append(filtered, record)
		}
		return filtered, nil
	})
}

func (store *workloadStore) Clear() error {
	return store.transform(func(_ []workloadRecord) ([]workloadRecord, error) {
		return []workloadRecord{}, nil
	})
}

func (store *workloadStore) Get(machineName string) (workloadRecord, bool, error) {
	records, err := store.List()
	if err != nil {
		return workloadRecord{}, false, err
	}

	for _, record := range records {
		if record.Machine == strings.TrimSpace(machineName) {
			return record, true, nil
		}
	}

	return workloadRecord{}, false, nil
}

func (store *workloadStore) List() ([]workloadRecord, error) {
	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []workloadRecord{}, nil
		}
		return nil, fmt.Errorf("reading workload store: %w", err)
	}

	return decodeWorkloadRecords(raw)
}

func (store *workloadStore) ByNode(nodeName string) ([]workloadRecord, error) {
	all, err := store.List()
	if err != nil {
		return nil, err
	}

	result := make([]workloadRecord, 0)
	for _, record := range all {
		if strings.TrimSpace(record.Node) == strings.TrimSpace(nodeName) {
			result = append(result, record)
		}
	}
	return result, nil
}

func decodeWorkloadRecords(raw []byte) ([]workloadRecord, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []workloadRecord{}, nil
	}

	records := []workloadRecord{}
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing workload store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Machine < records[j].Machine
	})

	return records, nil
}

func encodeWorkloadRecords(records []workloadRecord) ([]byte, error) {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing workload store: %w", err)
	}
	return raw, nil
}

func (store *workloadStore) transform(fn func([]workloadRecord) ([]workloadRecord, error)) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("creating workload store directory: %w", err)
	}

	return lockedfile.Transform(store.path, func(raw []byte) ([]byte, error) {
		records, err := decodeWorkloadRecords(raw)
		if err != nil {
			return nil, err
		}

		updated, err := fn(records)
		if err != nil {
			return nil, err
		}

		return encodeWorkloadRecords(updated)
	})
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
