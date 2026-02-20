// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"unikctl.sh/internal/operations"
)

func tenantScopeFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	for _, candidate := range []string{
		r.Header.Get("X-Tenant-ID"),
		r.URL.Query().Get("tenant"),
		os.Getenv("UNIKCTL_TENANT"),
	} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		return normalizeTenant(candidate), true
	}

	return "", false
}

func (server *Server) tenantMachineSet(tenant string) (map[string]struct{}, error) {
	if server == nil || server.workloads == nil {
		return map[string]struct{}{}, nil
	}

	records, err := server.workloads.ByTenant(tenant)
	if err != nil {
		return nil, err
	}

	set := map[string]struct{}{}
	for _, record := range records {
		machine := strings.TrimSpace(record.Machine)
		if machine == "" {
			continue
		}
		set[machine] = struct{}{}
	}

	return set, nil
}

func (server *Server) tenantNodeSet(tenant string) (map[string]struct{}, error) {
	if server == nil || server.workloads == nil {
		return map[string]struct{}{}, nil
	}

	records, err := server.workloads.ByTenant(tenant)
	if err != nil {
		return nil, err
	}

	set := map[string]struct{}{}
	for _, record := range records {
		node := strings.TrimSpace(record.Node)
		if node == "" {
			continue
		}
		set[node] = struct{}{}
	}

	return set, nil
}

func (server *Server) ensureTenantMachineAccess(machineName, tenant string) error {
	if server == nil || server.workloads == nil {
		return fmt.Errorf("deployment not found")
	}

	machineName = strings.TrimSpace(machineName)
	if machineName == "" {
		return fmt.Errorf("machine name is required")
	}

	record, found, err := server.workloads.Get(machineName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("deployment not found")
	}

	if normalizeTenant(record.Tenant) != normalizeTenant(tenant) {
		return fmt.Errorf("deployment not found")
	}

	return nil
}

func operationVisibleToTenant(record operations.Record, tenant string, tenantMachines map[string]struct{}) bool {
	if len(tenantMachines) == 0 {
		return normalizeTenant(record.Tenant) == normalizeTenant(tenant)
	}

	if machine := strings.TrimSpace(record.Machine); machine != "" {
		_, ok := tenantMachines[machine]
		return ok
	}

	if strings.TrimSpace(record.Tenant) != "" {
		return normalizeTenant(record.Tenant) == normalizeTenant(tenant)
	}

	for _, target := range record.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := tenantMachines[target]; ok {
			return true
		}
	}

	// Without an attached machine/target we cannot attribute this operation safely.
	return false
}
