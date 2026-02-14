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

type nodeState string

const (
	nodeStateReady    nodeState = "ready"
	nodeStateCordoned nodeState = "cordoned"
	nodeStateDraining nodeState = "draining"
	nodeStateOffline  nodeState = "offline"

	nodeHeartbeatStaleAfter = 30 * time.Second
	nodeStoreFileName       = "nodes.json"
)

type nodeRecord struct {
	Name             string            `json:"name"`
	Address          string            `json:"address"`
	AgentURL         string            `json:"agent_url"`
	AgentToken       string            `json:"agent_token,omitempty"`
	State            nodeState         `json:"state"`
	Cordoned         bool              `json:"cordoned"`
	Draining         bool              `json:"draining"`
	Labels           map[string]string `json:"labels,omitempty"`
	CapacityCPUMilli int64             `json:"capacity_cpu_milli,omitempty"`
	CapacityMemBytes int64             `json:"capacity_mem_bytes,omitempty"`
	UsedCPUMilli     int64             `json:"used_cpu_milli,omitempty"`
	UsedMemBytes     int64             `json:"used_mem_bytes,omitempty"`
	Machines         int               `json:"machines,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	HeartbeatAt      time.Time         `json:"heartbeat_at"`
}

type nodeStore struct {
	path string
}

func newNodeStore(ctx context.Context) (*nodeStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	return &nodeStore{
		path: filepath.Join(runtimeDir, nodeStoreFileName),
	}, nil
}

func (store *nodeStore) Register(request controlplaneapi.NodeRegisterRequest) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.transform(func(records []nodeRecord) ([]nodeRecord, error) {
		normalizedName := strings.TrimSpace(request.Name)
		if normalizedName == "" {
			return nil, fmt.Errorf("node name is required")
		}

		for i := range records {
			if records[i].Name != normalizedName {
				continue
			}

			records[i].Address = strings.TrimSpace(request.Address)
			records[i].AgentURL = strings.TrimSpace(request.AgentURL)
			records[i].AgentToken = strings.TrimSpace(request.AgentToken)
			records[i].Labels = cloneLabels(request.Labels)
			records[i].CapacityCPUMilli = request.CapacityCPUMilli
			records[i].CapacityMemBytes = request.CapacityMemBytes
			records[i].UsedCPUMilli = request.UsedCPUMilli
			records[i].UsedMemBytes = request.UsedMemBytes
			records[i].Machines = request.Machines
			records[i].HeartbeatAt = now
			records[i].UpdatedAt = now
			if !records[i].Cordoned && !records[i].Draining {
				records[i].State = nodeStateReady
			}
			record = records[i]
			return records, nil
		}

		record = nodeRecord{
			Name:             normalizedName,
			Address:          strings.TrimSpace(request.Address),
			AgentURL:         strings.TrimSpace(request.AgentURL),
			AgentToken:       strings.TrimSpace(request.AgentToken),
			State:            nodeStateReady,
			Cordoned:         false,
			Draining:         false,
			Labels:           cloneLabels(request.Labels),
			CapacityCPUMilli: request.CapacityCPUMilli,
			CapacityMemBytes: request.CapacityMemBytes,
			UsedCPUMilli:     request.UsedCPUMilli,
			UsedMemBytes:     request.UsedMemBytes,
			Machines:         request.Machines,
			CreatedAt:        now,
			UpdatedAt:        now,
			HeartbeatAt:      now,
		}
		records = append(records, record)
		return records, nil
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) Heartbeat(request controlplaneapi.NodeHeartbeatRequest) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.transform(func(records []nodeRecord) ([]nodeRecord, error) {
		name := strings.TrimSpace(request.Name)
		if name == "" {
			return nil, fmt.Errorf("node name is required")
		}

		for i := range records {
			if records[i].Name != name {
				continue
			}

			if strings.TrimSpace(request.Address) != "" {
				records[i].Address = strings.TrimSpace(request.Address)
			}
			if strings.TrimSpace(request.AgentURL) != "" {
				records[i].AgentURL = strings.TrimSpace(request.AgentURL)
			}
			if len(request.Labels) > 0 {
				records[i].Labels = cloneLabels(request.Labels)
			}
			if request.CapacityCPUMilli > 0 {
				records[i].CapacityCPUMilli = request.CapacityCPUMilli
			}
			if request.CapacityMemBytes > 0 {
				records[i].CapacityMemBytes = request.CapacityMemBytes
			}
			records[i].UsedCPUMilli = request.UsedCPUMilli
			records[i].UsedMemBytes = request.UsedMemBytes
			records[i].Machines = request.Machines
			records[i].HeartbeatAt = now
			records[i].UpdatedAt = now
			if records[i].Draining {
				records[i].State = nodeStateDraining
			} else if records[i].Cordoned {
				records[i].State = nodeStateCordoned
			} else {
				records[i].State = nodeStateReady
			}

			record = records[i]
			return records, nil
		}

		return nil, fmt.Errorf("node not registered: %s", name)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) Get(name string) (nodeRecord, bool, error) {
	records, err := store.List()
	if err != nil {
		return nodeRecord{}, false, err
	}

	for _, record := range records {
		if record.Name == strings.TrimSpace(name) {
			return record, true, nil
		}
	}

	return nodeRecord{}, false, nil
}

func (store *nodeStore) List() ([]nodeRecord, error) {
	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []nodeRecord{}, nil
		}
		return nil, fmt.Errorf("reading node store: %w", err)
	}

	return decodeNodeRecords(raw)
}

func (store *nodeStore) MarkOfflineStale(maxAge time.Duration) error {
	now := time.Now().UTC()
	return store.transform(func(records []nodeRecord) ([]nodeRecord, error) {
		for i := range records {
			if records[i].HeartbeatAt.IsZero() || now.Sub(records[i].HeartbeatAt) > maxAge {
				records[i].State = nodeStateOffline
				records[i].UpdatedAt = now
			}
		}

		return records, nil
	})
}

func (store *nodeStore) SetCordon(name string, cordoned bool) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.transform(func(records []nodeRecord) ([]nodeRecord, error) {
		for i := range records {
			if records[i].Name != strings.TrimSpace(name) {
				continue
			}

			records[i].Cordoned = cordoned
			if !cordoned {
				records[i].Draining = false
				records[i].State = nodeStateReady
			} else if records[i].Draining {
				records[i].State = nodeStateDraining
			} else {
				records[i].State = nodeStateCordoned
			}
			records[i].UpdatedAt = now
			record = records[i]
			return records, nil
		}

		return nil, fmt.Errorf("node not found: %s", name)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) SetDraining(name string, draining bool) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.transform(func(records []nodeRecord) ([]nodeRecord, error) {
		for i := range records {
			if records[i].Name != strings.TrimSpace(name) {
				continue
			}

			records[i].Draining = draining
			if draining {
				records[i].Cordoned = true
				records[i].State = nodeStateDraining
			} else if records[i].Cordoned {
				records[i].State = nodeStateCordoned
			} else {
				records[i].State = nodeStateReady
			}
			records[i].UpdatedAt = now
			record = records[i]
			return records, nil
		}

		return nil, fmt.Errorf("node not found: %s", name)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func decodeNodeRecords(raw []byte) ([]nodeRecord, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []nodeRecord{}, nil
	}

	records := []nodeRecord{}
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing node store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})

	return records, nil
}

func encodeNodeRecords(records []nodeRecord) ([]byte, error) {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing node store: %w", err)
	}
	return raw, nil
}

func (store *nodeStore) transform(fn func([]nodeRecord) ([]nodeRecord, error)) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("creating node store directory: %w", err)
	}

	return lockedfile.Transform(store.path, func(raw []byte) ([]byte, error) {
		records, err := decodeNodeRecords(raw)
		if err != nil {
			return nil, err
		}

		updated, err := fn(records)
		if err != nil {
			return nil, err
		}

		return encodeNodeRecords(updated)
	})
}

func cloneLabels(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}

	cloned := map[string]string{}
	for key, value := range source {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		cloned[key] = strings.TrimSpace(value)
	}
	return cloned
}
