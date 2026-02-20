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
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"

	"unikctl.sh/config"
	"unikctl.sh/internal/walstore"
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
	Tenant    string    `json:"tenant,omitempty"`
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
	backend *walstore.Store
}

type StartOptions struct {
	TraceID        string
	IdempotencyKey string
	Tenant         string
}

const (
	defaultHistoryLimit = 256
	defaultListLimit    = 30
	operationsDBDirName = "operations.db"
)

func NewStore(ctx context.Context) (*Store, error) {
	runtimeDir := strings.TrimSpace(config.G[config.KraftKit](ctx).RuntimeDir)
	if runtimeDir == "" {
		return nil, fmt.Errorf("runtime directory is not configured")
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating runtime directory: %w", err)
	}

	backend, err := walstore.Open(filepath.Join(runtimeDir, operationsDBDirName))
	if err != nil {
		return nil, err
	}

	return &Store{backend: backend}, nil
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

	err := store.backend.Update(func(txn *badger.Txn) error {
		idemKey := strings.TrimSpace(opts.IdempotencyKey)
		if idemKey != "" {
			var operationID string
			found, err := walstore.GetJSON(txn, idemIndexKey(kind, idemKey), &operationID)
			if err != nil {
				return err
			}

			if found && strings.TrimSpace(operationID) != "" {
				foundRecord, ok, err := getRecordTxn(txn, operationID)
				if err != nil {
					return err
				}
				if ok {
					record = foundRecord
					reused = true
					return nil
				}
			}
		}

		record = Record{
			ID:        newID(),
			Kind:      kind,
			State:     StatePending,
			Targets:   append([]string{}, targets...),
			Tenant:    strings.TrimSpace(opts.Tenant),
			TraceID:   strings.TrimSpace(opts.TraceID),
			IdemKey:   strings.TrimSpace(opts.IdempotencyKey),
			Message:   message,
			CreatedAt: now,
			UpdatedAt: now,
		}

		if err := setRecordTxn(txn, record); err != nil {
			return err
		}

		if record.IdemKey != "" {
			if err := walstore.SetJSON(txn, idemIndexKey(kind, record.IdemKey), record.ID); err != nil {
				return err
			}
		}

		return pruneHistoryTxn(txn, defaultHistoryLimit)
	})
	if err != nil {
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
	record := Record{}
	ok := false
	err := store.backend.View(func(txn *badger.Txn) error {
		found, getErr := walstore.GetJSON(txn, recordKey(id), &record)
		if getErr != nil {
			return getErr
		}
		ok = found
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading operation store: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("operation not found: %s", id)
	}

	return &record, nil
}

func (store *Store) List(limit int) ([]Record, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}

	records := []Record{}
	err := store.backend.View(func(txn *badger.Txn) error {
		all, listErr := listRecordsTxn(txn)
		if listErr != nil {
			return listErr
		}
		records = all
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading operation store: %w", err)
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].CreatedAt.After(records[j].CreatedAt)
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})

	if len(records) > limit {
		records = records[:limit]
	}

	return records, nil
}

func (store *Store) update(id string, updateFn func(record *Record)) error {
	return store.backend.Update(func(txn *badger.Txn) error {
		record, ok, err := getRecordTxn(txn, id)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("operation not found: %s", id)
		}

		updateFn(&record)
		record.UpdatedAt = time.Now().UTC()
		return setRecordTxn(txn, record)
	})
}

func setRecordTxn(txn *badger.Txn, record Record) error {
	return walstore.SetJSON(txn, recordKey(record.ID), record)
}

func getRecordTxn(txn *badger.Txn, id string) (Record, bool, error) {
	record := Record{}
	ok, err := walstore.GetJSON(txn, recordKey(id), &record)
	return record, ok, err
}

func listRecordsTxn(txn *badger.Txn) ([]Record, error) {
	records := []Record{}
	iterator := txn.NewIterator(badger.IteratorOptions{
		PrefetchValues: true,
		PrefetchSize:   50,
	})
	defer iterator.Close()

	prefix := []byte("op/")
	for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
		item := iterator.Item()
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return nil, err
		}

		record := Record{}
		if err := jsonUnmarshal(raw, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func pruneHistoryTxn(txn *badger.Txn, keep int) error {
	if keep <= 0 {
		return nil
	}

	records, err := listRecordsTxn(txn)
	if err != nil {
		return err
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})

	if len(records) <= keep {
		return nil
	}

	for _, stale := range records[keep:] {
		if err := walstore.Delete(txn, recordKey(stale.ID)); err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if stale.IdemKey != "" {
			if err := walstore.Delete(txn, idemIndexKey(stale.Kind, stale.IdemKey)); err != nil && err != badger.ErrKeyNotFound {
				return err
			}
		}
	}

	return nil
}

func recordKey(id string) string {
	return "op/" + strings.TrimSpace(id)
}

func idemIndexKey(kind Kind, idem string) string {
	return fmt.Sprintf("idem/%s/%s", kind, strings.TrimSpace(idem))
}

func jsonUnmarshal(raw []byte, out any) error {
	return json.Unmarshal(raw, out)
}

func newID() string {
	random := make([]byte, 5)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}

	return fmt.Sprintf("op-%d-%s", time.Now().UTC().Unix(), hex.EncodeToString(random))
}
