// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"

	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/walstore"
)

const jobQueueDirName = "jobs.db"

type queueJobState string

const (
	queueJobPending  queueJobState = "pending"
	queueJobInflight queueJobState = "inflight"
	queueJobFailed   queueJobState = "failed"
)

type durableJob struct {
	OperationID string                          `json:"operation_id"`
	TraceID     string                          `json:"trace_id,omitempty"`
	Attempt     int                             `json:"attempt"`
	Deploy      *controlplaneapi.DeployRequest  `json:"deploy,omitempty"`
	Destroy     *controlplaneapi.DestroyRequest `json:"destroy,omitempty"`
	Kind        string                          `json:"kind"`
	State       queueJobState                   `json:"state"`
	NextRunAt   time.Time                       `json:"next_run_at"`
	LeaseOwner  string                          `json:"lease_owner,omitempty"`
	LeaseUntil  time.Time                       `json:"lease_until,omitempty"`
	LastError   string                          `json:"last_error,omitempty"`
	UpdatedAt   time.Time                       `json:"updated_at"`
}

type jobQueue struct {
	backend *walstore.Store
}

func newJobQueue(runtimeDir string) (*jobQueue, error) {
	backend, err := walstore.Open(filepath.Join(runtimeDir, jobQueueDirName))
	if err != nil {
		return nil, err
	}
	return &jobQueue{backend: backend}, nil
}

func (queue *jobQueue) Enqueue(queued job) error {
	now := time.Now().UTC()
	record := durableJob{
		OperationID: strings.TrimSpace(queued.operationID),
		TraceID:     strings.TrimSpace(queued.traceID),
		Attempt:     queued.attempt,
		Deploy:      queued.deploy,
		Destroy:     queued.destroy,
		Kind:        string(queued.kind()),
		State:       queueJobPending,
		NextRunAt:   now,
		UpdatedAt:   now,
	}

	if record.OperationID == "" {
		return fmt.Errorf("operation ID is required")
	}

	return queue.backend.Update(func(txn *badger.Txn) error {
		found, err := walstore.GetJSON(txn, queueJobKey(record.OperationID), &durableJob{})
		if err != nil {
			return err
		}
		if found {
			return nil
		}

		return walstore.SetJSON(txn, queueJobKey(record.OperationID), record)
	})
}

func (queue *jobQueue) Claim(owner string, lease time.Duration) (*job, bool, error) {
	now := time.Now().UTC()
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, false, fmt.Errorf("lease owner is required")
	}

	claimed := (*job)(nil)
	err := queue.backend.Update(func(txn *badger.Txn) error {
		records, err := queue.listPendingTxn(txn)
		if err != nil {
			return err
		}

		sort.SliceStable(records, func(i, j int) bool {
			if records[i].NextRunAt.Equal(records[j].NextRunAt) {
				return records[i].OperationID < records[j].OperationID
			}
			return records[i].NextRunAt.Before(records[j].NextRunAt)
		})

		for _, record := range records {
			if record.State == queueJobFailed {
				continue
			}

			leaseExpired := record.LeaseUntil.IsZero() || !record.LeaseUntil.After(now)
			ready := !record.NextRunAt.After(now)
			if !ready || !leaseExpired {
				continue
			}

			record.State = queueJobInflight
			record.LeaseOwner = owner
			record.LeaseUntil = now.Add(lease)
			record.UpdatedAt = now
			if err := walstore.SetJSON(txn, queueJobKey(record.OperationID), record); err != nil {
				return err
			}

			claimed = &job{
				operationID: record.OperationID,
				traceID:     record.TraceID,
				attempt:     record.Attempt,
				deploy:      record.Deploy,
				destroy:     record.Destroy,
			}
			return nil
		}

		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if claimed == nil {
		return nil, false, nil
	}
	return claimed, true, nil
}

func (queue *jobQueue) Ack(operationID string) error {
	return queue.backend.Update(func(txn *badger.Txn) error {
		if err := walstore.Delete(txn, queueJobKey(operationID)); err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		return nil
	})
}

func (queue *jobQueue) Retry(queued job, backoff time.Duration, err error) error {
	return queue.backend.Update(func(txn *badger.Txn) error {
		record := durableJob{}
		found, getErr := walstore.GetJSON(txn, queueJobKey(queued.operationID), &record)
		if getErr != nil {
			return getErr
		}
		if !found {
			record = durableJob{
				OperationID: queued.operationID,
				TraceID:     queued.traceID,
				Deploy:      queued.deploy,
				Destroy:     queued.destroy,
				Kind:        string(queued.kind()),
			}
		}

		record.Attempt = queued.attempt
		record.State = queueJobPending
		record.NextRunAt = time.Now().UTC().Add(backoff)
		record.LeaseOwner = ""
		record.LeaseUntil = time.Time{}
		if err != nil {
			record.LastError = err.Error()
		}
		record.UpdatedAt = time.Now().UTC()
		return walstore.SetJSON(txn, queueJobKey(record.OperationID), record)
	})
}

func (queue *jobQueue) Fail(operationID string, err error) error {
	return queue.backend.Update(func(txn *badger.Txn) error {
		record := durableJob{}
		found, getErr := walstore.GetJSON(txn, queueJobKey(operationID), &record)
		if getErr != nil {
			return getErr
		}
		if !found {
			return nil
		}

		record.State = queueJobFailed
		record.LeaseOwner = ""
		record.LeaseUntil = time.Time{}
		record.NextRunAt = time.Time{}
		if err != nil {
			record.LastError = err.Error()
		}
		record.UpdatedAt = time.Now().UTC()
		return walstore.SetJSON(txn, queueJobKey(operationID), record)
	})
}

func (queue *jobQueue) listPendingTxn(txn *badger.Txn) ([]durableJob, error) {
	records := []durableJob{}
	iterator := txn.NewIterator(badger.IteratorOptions{
		PrefetchValues: true,
		PrefetchSize:   50,
	})
	defer iterator.Close()

	prefix := []byte("job/")
	for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
		item := iterator.Item()
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return nil, err
		}
		record := durableJob{}
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func queueJobKey(operationID string) string {
	return "job/" + strings.TrimSpace(operationID)
}
