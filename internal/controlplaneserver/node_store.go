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

type nodeState string

const (
	nodeStateReady    nodeState = "ready"
	nodeStateCordoned nodeState = "cordoned"
	nodeStateDraining nodeState = "draining"
	nodeStateOffline  nodeState = "offline"

	nodeHeartbeatStaleAfter = 30 * time.Second
	nodeStoreDirName        = "nodes.db"
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
	backend *walstore.Store
}

func newNodeStore(ctx context.Context) (*nodeStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	backend, err := walstore.Open(filepath.Join(runtimeDir, nodeStoreDirName))
	if err != nil {
		return nil, err
	}

	return &nodeStore{backend: backend}, nil
}

func (store *nodeStore) Register(request controlplaneapi.NodeRegisterRequest) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.backend.Update(func(txn *badger.Txn) error {
		normalizedName := strings.TrimSpace(request.Name)
		if normalizedName == "" {
			return fmt.Errorf("node name is required")
		}

		existing, found, err := store.getTxn(txn, normalizedName)
		if err != nil {
			return err
		}

		if found {
			existing.Address = strings.TrimSpace(request.Address)
			existing.AgentURL = strings.TrimSpace(request.AgentURL)
			existing.AgentToken = strings.TrimSpace(request.AgentToken)
			existing.Labels = cloneLabels(request.Labels)
			existing.CapacityCPUMilli = request.CapacityCPUMilli
			existing.CapacityMemBytes = request.CapacityMemBytes
			existing.UsedCPUMilli = request.UsedCPUMilli
			existing.UsedMemBytes = request.UsedMemBytes
			existing.Machines = request.Machines
			existing.HeartbeatAt = now
			existing.UpdatedAt = now
			if !existing.Cordoned && !existing.Draining {
				existing.State = nodeStateReady
			}
			record = existing
			return store.setTxn(txn, existing)
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
		return store.setTxn(txn, record)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) Heartbeat(request controlplaneapi.NodeHeartbeatRequest) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.backend.Update(func(txn *badger.Txn) error {
		name := strings.TrimSpace(request.Name)
		if name == "" {
			return fmt.Errorf("node name is required")
		}

		existing, found, err := store.getTxn(txn, name)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("node not registered: %s", name)
		}

		if strings.TrimSpace(request.Address) != "" {
			existing.Address = strings.TrimSpace(request.Address)
		}
		if strings.TrimSpace(request.AgentURL) != "" {
			existing.AgentURL = strings.TrimSpace(request.AgentURL)
		}
		if len(request.Labels) > 0 {
			existing.Labels = cloneLabels(request.Labels)
		}
		if request.CapacityCPUMilli > 0 {
			existing.CapacityCPUMilli = request.CapacityCPUMilli
		}
		if request.CapacityMemBytes > 0 {
			existing.CapacityMemBytes = request.CapacityMemBytes
		}
		existing.UsedCPUMilli = request.UsedCPUMilli
		existing.UsedMemBytes = request.UsedMemBytes
		existing.Machines = request.Machines
		existing.HeartbeatAt = now
		existing.UpdatedAt = now
		if existing.Draining {
			existing.State = nodeStateDraining
		} else if existing.Cordoned {
			existing.State = nodeStateCordoned
		} else {
			existing.State = nodeStateReady
		}

		record = existing
		return store.setTxn(txn, existing)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) Get(name string) (nodeRecord, bool, error) {
	record := nodeRecord{}
	found := false
	err := store.backend.View(func(txn *badger.Txn) error {
		var getErr error
		record, found, getErr = store.getTxn(txn, strings.TrimSpace(name))
		return getErr
	})
	if err != nil {
		return nodeRecord{}, false, err
	}

	return record, found, nil
}

func (store *nodeStore) List() ([]nodeRecord, error) {
	records := []nodeRecord{}
	err := store.backend.View(func(txn *badger.Txn) error {
		iterator := txn.NewIterator(badger.IteratorOptions{
			PrefetchValues: true,
			PrefetchSize:   20,
		})
		defer iterator.Close()

		prefix := []byte("node/")
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			item := iterator.Item()
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			record := nodeRecord{}
			if err := json.Unmarshal(raw, &record); err != nil {
				return err
			}
			records = append(records, record)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading node store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})

	return records, nil
}

func (store *nodeStore) MarkOfflineStale(maxAge time.Duration) error {
	now := time.Now().UTC()
	return store.backend.Update(func(txn *badger.Txn) error {
		records, err := store.listTxn(txn)
		if err != nil {
			return err
		}

		for _, record := range records {
			if record.HeartbeatAt.IsZero() || now.Sub(record.HeartbeatAt) > maxAge {
				record.State = nodeStateOffline
				record.UpdatedAt = now
				if err := store.setTxn(txn, record); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (store *nodeStore) SetCordon(name string, cordoned bool) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.backend.Update(func(txn *badger.Txn) error {
		var found bool
		var err error
		record, found, err = store.getTxn(txn, strings.TrimSpace(name))
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("node not found: %s", name)
		}

		record.Cordoned = cordoned
		if !cordoned {
			record.Draining = false
			record.State = nodeStateReady
		} else if record.Draining {
			record.State = nodeStateDraining
		} else {
			record.State = nodeStateCordoned
		}
		record.UpdatedAt = now
		return store.setTxn(txn, record)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) SetDraining(name string, draining bool) (nodeRecord, error) {
	now := time.Now().UTC()
	record := nodeRecord{}

	err := store.backend.Update(func(txn *badger.Txn) error {
		var found bool
		var err error
		record, found, err = store.getTxn(txn, strings.TrimSpace(name))
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("node not found: %s", name)
		}

		record.Draining = draining
		if draining {
			record.Cordoned = true
			record.State = nodeStateDraining
		} else if record.Cordoned {
			record.State = nodeStateCordoned
		} else {
			record.State = nodeStateReady
		}
		record.UpdatedAt = now
		return store.setTxn(txn, record)
	})
	if err != nil {
		return nodeRecord{}, err
	}

	return record, nil
}

func (store *nodeStore) getTxn(txn *badger.Txn, name string) (nodeRecord, bool, error) {
	record := nodeRecord{}
	found, err := walstore.GetJSON(txn, nodeKey(name), &record)
	return record, found, err
}

func (store *nodeStore) listTxn(txn *badger.Txn) ([]nodeRecord, error) {
	records := []nodeRecord{}
	iterator := txn.NewIterator(badger.IteratorOptions{
		PrefetchValues: true,
		PrefetchSize:   20,
	})
	defer iterator.Close()

	prefix := []byte("node/")
	for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
		item := iterator.Item()
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return nil, err
		}

		record := nodeRecord{}
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func (store *nodeStore) setTxn(txn *badger.Txn, record nodeRecord) error {
	return walstore.SetJSON(txn, nodeKey(record.Name), record)
}

func nodeKey(name string) string {
	return "node/" + strings.TrimSpace(name)
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
