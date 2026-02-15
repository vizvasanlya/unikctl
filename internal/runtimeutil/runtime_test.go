// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package runtimeutil

import "testing"

func TestNormalizePreservesDigest(t *testing.T) {
	got := Normalize("base@sha256:abc123", "latest")
	want := RuntimeRegistryPrefix + "/base@sha256:abc123"
	if got != want {
		t.Fatalf("unexpected normalize result: got %q want %q", got, want)
	}
}

func TestCandidatesIncludeDigestLockFirst(t *testing.T) {
	candidates := Candidates("base:latest", "latest")
	if len(candidates) == 0 {
		t.Fatalf("expected runtime candidates, got none")
	}

	first := candidates[0]
	if first.Digest == "" {
		t.Fatalf("expected first candidate to be digest-locked, got: %+v", first)
	}

	if first.Name != RuntimeRegistryPrefix+"/base" {
		t.Fatalf("unexpected first candidate name: %q", first.Name)
	}
}

func TestCandidatesWithoutLockStillResolvable(t *testing.T) {
	candidates := Candidates("ghcr.io/example/custom:1.0.0", "latest")
	if len(candidates) == 0 {
		t.Fatalf("expected candidates for custom runtime")
	}

	for _, candidate := range candidates {
		if candidate.Digest != "" {
			t.Fatalf("did not expect digest-locked candidate for custom runtime: %+v", candidate)
		}
	}
}
