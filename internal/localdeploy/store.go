// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package localdeploy

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

const storeFileName = "local-deployments.json"

type RecoverSpec struct {
	Args         []string `json:"args,omitempty"`
	Debug        bool     `json:"debug,omitempty"`
	Memory       string   `json:"memory,omitempty"`
	Name         string   `json:"name,omitempty"`
	Rootfs       string   `json:"rootfs,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	Target       string   `json:"target,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Ports        []string `json:"ports,omitempty"`
}

type Record struct {
	Machine            string     `json:"machine"`
	Spec               RecoverSpec `json:"spec"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastRecoverAttempt time.Time  `json:"last_recover_attempt,omitempty"`
	LastRecoverError   string     `json:"last_recover_error,omitempty"`
}

type Store struct {
	path string
}

func NewStore(ctx context.Context) (*Store, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	return &Store{
		path: filepath.Join(runtimeDir, storeFileName),
	}, nil
}

func (store *Store) Upsert(machineName string, spec RecoverSpec) error {
	now := time.Now().UTC()
	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return fmt.Errorf("machine name is required")
	}

	spec = sanitizeSpec(spec)
	spec.Name = machineName

	return store.transform(func(records []Record) ([]Record, error) {
		for i := range records {
			if records[i].Machine != machineName {
				continue
			}

			records[i].Spec = spec
			records[i].UpdatedAt = now
			return records, nil
		}

		records = append(records, Record{
			Machine:   machineName,
			Spec:      spec,
			CreatedAt: now,
			UpdatedAt: now,
		})

		return records, nil
	})
}

func (store *Store) RemoveMachines(names ...string) error {
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

	return store.transform(func(records []Record) ([]Record, error) {
		filtered := make([]Record, 0, len(records))
		for _, record := range records {
			if _, ok := targets[record.Machine]; ok {
				continue
			}
			filtered = append(filtered, record)
		}
		return filtered, nil
	})
}

func (store *Store) Clear() error {
	return store.transform(func(_ []Record) ([]Record, error) {
		return []Record{}, nil
	})
}

func (store *Store) List() ([]Record, error) {
	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{}, nil
		}
		return nil, fmt.Errorf("reading local deploy store: %w", err)
	}

	return decodeRecords(raw)
}

func (store *Store) MarkRecoverResult(machineName string, recoverErr error) error {
	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return nil
	}

	return store.transform(func(records []Record) ([]Record, error) {
		for i := range records {
			if records[i].Machine != machineName {
				continue
			}

			records[i].LastRecoverAttempt = time.Now().UTC()
			if recoverErr != nil {
				records[i].LastRecoverError = recoverErr.Error()
			} else {
				records[i].LastRecoverError = ""
			}
			records[i].UpdatedAt = time.Now().UTC()
			return records, nil
		}

		return records, nil
	})
}

func (store *Store) transform(fn func([]Record) ([]Record, error)) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("creating local deploy store directory: %w", err)
	}

	return lockedfile.Transform(store.path, func(raw []byte) ([]byte, error) {
		records, err := decodeRecords(raw)
		if err != nil {
			return nil, err
		}

		updated, err := fn(records)
		if err != nil {
			return nil, err
		}

		return encodeRecords(updated)
	})
}

func decodeRecords(raw []byte) ([]Record, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []Record{}, nil
	}

	records := []Record{}
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing local deploy store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Machine < records[j].Machine
	})

	return records, nil
}

func encodeRecords(records []Record) ([]byte, error) {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing local deploy store: %w", err)
	}
	return raw, nil
}

func sanitizeSpec(spec RecoverSpec) RecoverSpec {
	spec.Args = append([]string{}, spec.Args...)
	spec.Ports = append([]string{}, spec.Ports...)
	spec.Memory = strings.TrimSpace(spec.Memory)
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Rootfs = strings.TrimSpace(spec.Rootfs)
	spec.Runtime = strings.TrimSpace(spec.Runtime)
	spec.Target = strings.TrimSpace(spec.Target)
	spec.Platform = strings.TrimSpace(spec.Platform)
	spec.Architecture = strings.TrimSpace(spec.Architecture)
	return spec
}
