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
	"unikctl.sh/internal/lockedfile"
)

const serviceStoreFileName = "services.json"

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
	path string
}

func newServiceStore(ctx context.Context) (*serviceStore, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	return &serviceStore{
		path: filepath.Join(runtimeDir, serviceStoreFileName),
	}, nil
}

func (store *serviceStore) Get(name string) (serviceRecord, bool, error) {
	records, err := store.List()
	if err != nil {
		return serviceRecord{}, false, err
	}

	for _, record := range records {
		if record.Name == strings.TrimSpace(name) {
			return record, true, nil
		}
	}

	return serviceRecord{}, false, nil
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

	return store.transform(func(records []serviceRecord) ([]serviceRecord, error) {
		for i := range records {
			if records[i].Name != name {
				continue
			}

			records[i].Strategy = strings.TrimSpace(strategy)
			records[i].Phase = strings.TrimSpace(phase)
			records[i].Message = strings.TrimSpace(message)
			records[i].LastError = strings.TrimSpace(lastError)
			records[i].Desired = desired
			records[i].Current = normalizeStringSlice(current)
			records[i].UpdatedAt = now
			if healthy {
				records[i].LastHealthy = now
			}
			return records, nil
		}

		record := serviceRecord{
			Name:      name,
			Strategy:  strings.TrimSpace(strategy),
			Phase:     strings.TrimSpace(phase),
			Message:   strings.TrimSpace(message),
			LastError: strings.TrimSpace(lastError),
			Desired:   desired,
			Current:   normalizeStringSlice(current),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if healthy {
			record.LastHealthy = now
		}
		records = append(records, record)
		return records, nil
	})
}

func (store *serviceStore) List() ([]serviceRecord, error) {
	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []serviceRecord{}, nil
		}
		return nil, fmt.Errorf("reading service store: %w", err)
	}

	return decodeServiceRecords(raw)
}

func decodeServiceRecords(raw []byte) ([]serviceRecord, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []serviceRecord{}, nil
	}

	records := []serviceRecord{}
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing service store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})

	return records, nil
}

func encodeServiceRecords(records []serviceRecord) ([]byte, error) {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing service store: %w", err)
	}
	return raw, nil
}

func (store *serviceStore) transform(fn func([]serviceRecord) ([]serviceRecord, error)) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("creating service store directory: %w", err)
	}

	return lockedfile.Transform(store.path, func(raw []byte) ([]byte, error) {
		records, err := decodeServiceRecords(raw)
		if err != nil {
			return nil, err
		}

		updated, err := fn(records)
		if err != nil {
			return nil, err
		}

		return encodeServiceRecords(updated)
	})
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
