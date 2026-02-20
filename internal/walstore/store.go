// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package walstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v3"
)

type Store struct {
	path string
	db   *badger.DB
}

func Open(path string) (*Store, error) {
	path = filepath.Clean(path)
	if path == "" {
		return nil, fmt.Errorf("wal store path is required")
	}

	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("creating wal store directory: %w", err)
	}

	options := badger.DefaultOptions(path)
	options.SyncWrites = true
	options.Logger = nil

	db, err := badger.Open(options)
	if err != nil {
		return nil, fmt.Errorf("opening wal store: %w", err)
	}

	return &Store{path: path, db: db}, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	return store.db.Close()
}

func (store *Store) View(fn func(*badger.Txn) error) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("wal store is not initialized")
	}
	return store.db.View(fn)
}

func (store *Store) Update(fn func(*badger.Txn) error) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("wal store is not initialized")
	}
	return store.db.Update(fn)
}

func SetJSON(txn *badger.Txn, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", key, err)
	}
	return txn.Set([]byte(key), raw)
}

func GetJSON(txn *badger.Txn, key string, out any) (bool, error) {
	item, err := txn.Get([]byte(key))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}

	raw, err := item.ValueCopy(nil)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("decoding %s: %w", key, err)
	}

	return true, nil
}

func Delete(txn *badger.Txn, key string) error {
	return txn.Delete([]byte(key))
}

