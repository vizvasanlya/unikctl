// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package platform

import (
	"testing"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
)

func TestPreferredPlatformOrder_FirecrackerFirst(t *testing.T) {
	strategies := map[Platform]machinev1alpha1.MachineService{
		PlatformQEMU:        nil,
		PlatformFirecracker: nil,
		PlatformXen:         nil,
	}

	order := preferredPlatformOrder(strategies)
	if len(order) != 3 {
		t.Fatalf("unexpected order length: got=%d want=%d", len(order), 3)
	}

	if order[0] != PlatformFirecracker {
		t.Fatalf("expected firecracker first, got=%s", order[0])
	}
	if order[1] != PlatformQEMU {
		t.Fatalf("expected qemu second, got=%s", order[1])
	}
	if order[2] != PlatformXen {
		t.Fatalf("expected xen third, got=%s", order[2])
	}
}

