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
	"unikctl.sh/internal/walstore"
)

const serviceStoreDirName = "services.db"

type serviceRecord struct {
	Name        string    `json:"name"`
	Strategy    string    `json:"strategy,omitempty"`
	Phase       string    `json:"phase,omitempty"`
	Message     string    `json:"message,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Desired     int       `json:"desired"`
	Current     []string  `json:"current,omitempty"`
	LastHealthy time.Time `json:"last_healthy,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type serviceStore struct {
	backend *walstore.Store
}

func newServiceStore(ctx context.Context) (*serviceStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	backend, err := walstore.Open(filepath.Join(runtimeDir, serviceStoreDirName))
	if err != nil {
		return nil, err
	}

	return &serviceStore{backend: backend}, nil
}

func (store *serviceStore) Get(name string) (serviceRecord, bool, error) {
	record := serviceRecord{}
	found := false
	err := store.backend.View(func(txn *badger.Txn) error {
		var getErr error
		found, getErr = walstore.GetJSON(txn, serviceKey(name), &record)
		return getErr
	})
	if err != nil {
		return serviceRecord{}, false, err
	}
	return record, found, nil
}

func (store *serviceStore) Upsert(name, strategy string, desired int, current []string, healthy bool) error {
	return store.UpsertState(name, strategy, desired, current, healthy, "ready", "rollout healthy", "")
}

func (store *serviceStore) UpsertState(name, strategy string, desired int, current []string, healthy bool, phase, message, lastError string) error {
	now := time.Now().UTC()
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("service name is required")
	}

	if desired < 1 {
		desired = 1
	}

	return store.backend.Update(func(txn *badger.Txn) error {
		record := serviceRecord{}
		found, err := walstore.GetJSON(txn, serviceKey(name), &record)
		if err != nil {
			return err
		}

		if !found {
			record = serviceRecord{
				Name:      name,
				CreatedAt: now,
			}
		}

		record.Strategy = strings.TrimSpace(strategy)
		record.Phase = strings.TrimSpace(phase)
		record.Message = strings.TrimSpace(message)
		record.LastError = strings.TrimSpace(lastError)
		record.Desired = desired
		record.Current = normalizeStringSlice(current)
		record.UpdatedAt = now
		if healthy {
			record.LastHealthy = now
		}

		return walstore.SetJSON(txn, serviceKey(name), record)
	})
}

func (store *serviceStore) List() ([]serviceRecord, error) {
	records := []serviceRecord{}
	err := store.backend.View(func(txn *badger.Txn) error {
		iterator := txn.NewIterator(badger.IteratorOptions{
			PrefetchValues: true,
			PrefetchSize:   20,
		})
		defer iterator.Close()

		prefix := []byte("service/")
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			item := iterator.Item()
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			record := serviceRecord{}
			if err := json.Unmarshal(raw, &record); err != nil {
				return err
			}
			records = append(records, record)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading service store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func serviceKey(name string) string {
	return "service/" + strings.TrimSpace(name)
}

func normalizeStringSlice(values []string) []string {
	ret := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ret = append(ret, value)
	}
	sort.Strings(ret)
	return ret
}
