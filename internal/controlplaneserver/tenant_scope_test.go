// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"path/filepath"
	"testing"

	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
	"unikctl.sh/internal/walstore"
)

func TestTenantIsolation_AccessControlBetweenTenants(t *testing.T) {
	workloads := newTestWorkloadStore(t)
	server := &Server{workloads: workloads}

	if err := workloads.Upsert("tenant-a-app", "node-a", controlplaneapi.DeployRequest{
		Tenant: "tenant-a",
		CPU:    "1",
		Memory: "64Mi",
	}); err != nil {
		t.Fatalf("upsert tenant-a workload: %v", err)
	}
	if err := workloads.Upsert("tenant-b-app", "node-b", controlplaneapi.DeployRequest{
		Tenant: "tenant-b",
		CPU:    "1",
		Memory: "64Mi",
	}); err != nil {
		t.Fatalf("upsert tenant-b workload: %v", err)
	}

	if err := server.ensureTenantMachineAccess("tenant-a-app", "tenant-a"); err != nil {
		t.Fatalf("expected tenant-a to access its workload: %v", err)
	}
	if err := server.ensureTenantMachineAccess("tenant-b-app", "tenant-a"); err == nil {
		t.Fatalf("expected tenant-a access to tenant-b workload to be rejected")
	}
}

func TestTenantQuota_RejectsExceedingQuota(t *testing.T) {
	workloads := newTestWorkloadStore(t)
	server := &Server{
		workloads: workloads,
		tenantQuotas: map[string]tenantQuota{
			"tenant-a": {
				MaxInstances: 1,
				MaxCPUMilli:  2000,
				MaxMemBytes:  512 * 1024 * 1024,
			},
		},
	}

	if err := workloads.Upsert("tenant-a-app-1", "node-a", controlplaneapi.DeployRequest{
		Tenant: "tenant-a",
		CPU:    "1",
		Memory: "128Mi",
	}); err != nil {
		t.Fatalf("upsert existing tenant workload: %v", err)
	}

	err := server.enforceTenantQuota(&controlplaneapi.DeployRequest{
		Tenant: "tenant-a",
		CPU:    "1",
		Memory: "128Mi",
	})
	if err == nil {
		t.Fatalf("expected quota enforcement rejection")
	}

	status, code, _, ok := apiErrorParts(err)
	if !ok {
		t.Fatalf("expected structured api error, got: %v", err)
	}
	if status != 409 {
		t.Fatalf("unexpected status code: got=%d want=%d", status, 409)
	}
	if code != "tenant_quota_instances_exceeded" {
		t.Fatalf("unexpected error code: got=%q", code)
	}
}

func TestOperationVisibleToTenant(t *testing.T) {
	tenantMachines := map[string]struct{}{
		"tenant-a-app": {},
	}

	if !operationVisibleToTenant(operations.Record{
		Machine: "tenant-a-app",
	}, "tenant-a", tenantMachines) {
		t.Fatalf("expected tenant operation visibility for own machine")
	}

	if operationVisibleToTenant(operations.Record{
		Machine: "tenant-b-app",
	}, "tenant-a", tenantMachines) {
		t.Fatalf("did not expect tenant operation visibility for foreign machine")
	}
}

func newTestWorkloadStore(t *testing.T) *workloadStore {
	t.Helper()

	temp := t.TempDir()
	backend, err := walstore.Open(filepath.Join(temp, "workloads.db"))
	if err != nil {
		t.Fatalf("open test workload store: %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Close()
	})

	return &workloadStore{backend: backend}
}

