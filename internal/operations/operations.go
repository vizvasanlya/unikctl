// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"unikctl.sh/config"
	"unikctl.sh/internal/lockedfile"
)

type Kind string

const (
	KindDeploy  Kind = "deploy"
	KindDestroy Kind = "destroy"
)

type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSubmitted State = "submitted"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
)

type Record struct {
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	State     State     `json:"state"`
	Targets   []string  `json:"targets,omitempty"`
	Machine   string    `json:"machine,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	IdemKey   string    `json:"idempotency_key,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	Message   string    `json:"message,omitempty"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastTryAt time.Time `json:"last_try_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	path string
}

type StartOptions struct {
	TraceID        string
	IdempotencyKey string
}

const (
	defaultHistoryLimit = 256
	defaultListLimit    = 30
	storeFileName       = "operations.json"
)

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

func (store *Store) Start(kind Kind, targets []string, message string) (*Record, error) {
	record, _, err := store.StartIdempotent(kind, targets, message, StartOptions{})
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (store *Store) StartIdempotent(kind Kind, targets []string, message string, opts StartOptions) (*Record, bool, error) {
	now := time.Now().UTC()
	record := Record{}
	reused := false

	if err := store.transform(func(records []Record) ([]Record, error) {
		idemKey := strings.TrimSpace(opts.IdempotencyKey)
		if idemKey != "" {
			for _, existing := range records {
				if existing.Kind != kind || existing.IdemKey != idemKey {
					continue
				}

				record = existing
				reused = true
				return records, nil
			}
		}

		record = Record{
			ID:        newID(),
			Kind:      kind,
			State:     StatePending,
			Targets:   append([]string{}, targets...),
			TraceID:   strings.TrimSpace(opts.TraceID),
			IdemKey:   idemKey,
			Message:   message,
			CreatedAt: now,
			UpdatedAt: now,
		}

		records = append([]Record{record}, records...)
		if len(records) > defaultHistoryLimit {
			records = records[:defaultHistoryLimit]
		}

		return records, nil
	}); err != nil {
		return nil, false, err
	}

	return &record, reused, nil
}

func (store *Store) SetMachine(id, machineName string) error {
	return store.update(id, func(record *Record) {
		record.Machine = machineName
	})
}

func (store *Store) SetState(id string, state State, message string) error {
	return store.update(id, func(record *Record) {
		record.State = state
		record.Message = message
		if state != StateFailed {
			record.Error = ""
		}
	})
}

func (store *Store) Fail(id string, err error) error {
	if err == nil {
		return nil
	}

	return store.update(id, func(record *Record) {
		record.State = StateFailed
		record.Error = err.Error()
		record.Message = "operation failed"
	})
}

func (store *Store) IncrementAttempts(id string, message string) error {
	return store.update(id, func(record *Record) {
		record.Attempts++
		record.LastTryAt = time.Now().UTC()
		if strings.TrimSpace(message) != "" {
			record.Message = message
		}
	})
}

func (store *Store) Get(id string) (*Record, error) {
	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("operation not found: %s", id)
		}
		return nil, fmt.Errorf("reading operation store: %w", err)
	}

	records, err := decodeRecords(raw)
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.ID != id {
			continue
		}
		found := record
		return &found, nil
	}

	return nil, fmt.Errorf("operation not found: %s", id)
}

func (store *Store) List(limit int) ([]Record, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}

	raw, err := lockedfile.Read(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("reading operation store: %w", err)
	}

	records, err := decodeRecords(raw)
	if err != nil {
		return nil, err
	}

	if len(records) > limit {
		records = records[:limit]
	}

	return records, nil
}

func (store *Store) append(record Record) error {
	return store.transform(func(records []Record) ([]Record, error) {
		records = append([]Record{record}, records...)
		if len(records) > defaultHistoryLimit {
			records = records[:defaultHistoryLimit]
		}

		return records, nil
	})
}

func (store *Store) update(id string, updateFn func(record *Record)) error {
	return store.transform(func(records []Record) ([]Record, error) {
		for i := range records {
			if records[i].ID != id {
				continue
			}

			updateFn(&records[i])
			records[i].UpdatedAt = time.Now().UTC()
			return records, nil
		}

		return nil, fmt.Errorf("operation not found: %s", id)
	})
}

func (store *Store) transform(fn func([]Record) ([]Record, error)) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("creating operation store directory: %w", err)
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

	var records []Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing operation store: %w", err)
	}

	return records, nil
}

func encodeRecords(records []Record) ([]byte, error) {
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing operation store: %w", err)
	}

	return raw, nil
}

func newID() string {
	random := make([]byte, 5)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}

	return fmt.Sprintf("op-%d-%s", time.Now().UTC().Unix(), hex.EncodeToString(random))
}
