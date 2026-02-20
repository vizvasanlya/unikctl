// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package firecracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateSnapshotResumeLatency(t *testing.T) {
	temp := t.TempDir()
	metaPath := filepath.Join(temp, "snapshot.json")

	metadata := snapshotMetadata{
		Machine:        "app-a",
		StatePath:      filepath.Join(temp, "snapshot.state"),
		MemoryPath:     filepath.Join(temp, "snapshot.mem"),
		CreatedAt:      time.Now().UTC().Add(-50 * time.Millisecond),
		SnapshotNanos:  int64(25 * time.Millisecond),
		ReferenceCount: 1,
	}

	if err := writeSnapshotMetadata(metaPath, metadata); err != nil {
		t.Fatalf("write snapshot metadata: %v", err)
	}

	if err := updateSnapshotResumeLatency(&FirecrackerConfig{
		SnapshotMeta: metaPath,
	}); err != nil {
		t.Fatalf("update snapshot resume latency: %v", err)
	}

	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read snapshot metadata: %v", err)
	}

	updated := snapshotMetadata{}
	if err := json.Unmarshal(raw, &updated); err != nil {
		t.Fatalf("decode snapshot metadata: %v", err)
	}

	if updated.ResumeNanos <= 0 {
		t.Fatalf("expected positive resume latency, got=%d", updated.ResumeNanos)
	}
	if updated.ReferenceCount != 2 {
		t.Fatalf("expected reference count increment to 2, got=%d", updated.ReferenceCount)
	}
	if updated.LastUsedAt.IsZero() {
		t.Fatalf("expected last used timestamp to be set")
	}
}
