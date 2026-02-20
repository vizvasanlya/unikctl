// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplaneserver

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"unikctl.sh/internal/controlplaneapi"
)

type tenantQuota struct {
	MaxInstances int64
	MaxCPUMilli  int64
	MaxMemBytes  int64
}

type tenantUsage struct {
	Instances int64
	CPUMilli  int64
	MemBytes  int64
}

func parseTenantQuotas(raw string) (map[string]tenantQuota, error) {
	quotas := map[string]tenantQuota{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return quotas, nil
	}

	// Format:
	// tenant-a:instances=10,cpu=8000m,mem=16Gi;tenant-b:instances=2,cpu=2000m,mem=2Gi
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		tenant, configRaw, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("invalid tenant quota entry %q: expected tenant:key=value,key=value", entry)
		}
		tenant = normalizeTenant(tenant)
		if tenant == "" {
			return nil, fmt.Errorf("tenant name cannot be empty in quota entry")
		}

		quota := tenantQuota{}
		for _, pair := range strings.Split(configRaw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}

			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return nil, fmt.Errorf("invalid quota setting %q in tenant %s", pair, tenant)
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			switch key {
			case "instances":
				parsed, err := parseInt64EnvLike(value)
				if err != nil {
					return nil, fmt.Errorf("invalid instances quota for tenant %s: %w", tenant, err)
				}
				quota.MaxInstances = parsed
			case "cpu":
				qty, err := resource.ParseQuantity(value)
				if err != nil {
					return nil, fmt.Errorf("invalid CPU quota for tenant %s: %w", tenant, err)
				}
				quota.MaxCPUMilli = qty.MilliValue()
			case "mem", "memory":
				qty, err := resource.ParseQuantity(value)
				if err != nil {
					return nil, fmt.Errorf("invalid memory quota for tenant %s: %w", tenant, err)
				}
				quota.MaxMemBytes = qty.Value()
			default:
				return nil, fmt.Errorf("unsupported tenant quota key %q", key)
			}
		}

		quotas[tenant] = quota
	}

	return quotas, nil
}

func (server *Server) enforceTenantQuota(request *controlplaneapi.DeployRequest) error {
	if request == nil || len(server.tenantQuotas) == 0 {
		return nil
	}

	tenant := normalizeTenant(request.Tenant)
	quota, ok := server.tenantQuotas[tenant]
	if !ok {
		quota, ok = server.tenantQuotas["default"]
		if !ok {
			return nil
		}
	}

	usage, err := server.tenantUsage(tenant)
	if err != nil {
		return err
	}

	nextInstances := usage.Instances + 1
	nextCPUMilli := usage.CPUMilli + requestedCPUMilli(request)
	nextMemBytes := usage.MemBytes + requestedMemoryBytes(request)

	if quota.MaxInstances > 0 && nextInstances > quota.MaxInstances {
		return newAdmissionError("tenant_quota_instances_exceeded", fmt.Sprintf("tenant %s instances quota exceeded", tenant))
	}
	if quota.MaxCPUMilli > 0 && nextCPUMilli > quota.MaxCPUMilli {
		return newAdmissionError("tenant_quota_cpu_exceeded", fmt.Sprintf("tenant %s cpu quota exceeded", tenant))
	}
	if quota.MaxMemBytes > 0 && nextMemBytes > quota.MaxMemBytes {
		return newAdmissionError("tenant_quota_memory_exceeded", fmt.Sprintf("tenant %s memory quota exceeded", tenant))
	}

	return nil
}

func (server *Server) tenantUsage(tenant string) (tenantUsage, error) {
	records, err := server.workloads.ByTenant(tenant)
	if err != nil {
		return tenantUsage{}, err
	}

	usage := tenantUsage{}
	for _, record := range records {
		usage.Instances++
		usage.CPUMilli += record.RequestedCPUMilli
		usage.MemBytes += record.RequestedMemBytes
	}
	return usage, nil
}

func parseInt64EnvLike(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("value is empty")
	}
	var value int64
	_, err := fmt.Sscanf(raw, "%d", &value)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("value cannot be negative")
	}
	return value, nil
}
