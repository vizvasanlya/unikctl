// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"testing"
	"time"
)

func TestRetryBackoffUsesExpectedRanges(t *testing.T) {
	for _, test := range []struct {
		attempt int
		base    time.Duration
	}{
		{attempt: 1, base: 1 * time.Second},
		{attempt: 2, base: 2 * time.Second},
		{attempt: 3, base: 4 * time.Second},
		{attempt: 4, base: 4 * time.Second},
	} {
		backoff := retryBackoff(test.attempt)
		min := test.base
		max := test.base + (test.base / 4)
		if backoff < min || backoff > max {
			t.Fatalf("unexpected backoff range for attempt %d: got=%s expected range [%s,%s]", test.attempt, backoff, min, max)
		}
	}
}
