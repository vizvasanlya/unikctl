// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package substrate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
	mplatform "unikctl.sh/machine/platform"
)

type SubstrateOptions struct{}

type statusOptions struct {
	Output string `long:"output" short:"o" usage:"Output format: table,json,yaml,list" default:"table"`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&SubstrateOptions{}, cobra.Command{
		Use:   "substrate",
		Short: "Substrate diagnostics",
		Long:  "Show substrate-level orchestration and density state.",
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	statusCmd, err := cmdfactory.New(&statusOptions{}, cobra.Command{
		Use:   "status",
		Short: "Show substrate maturity/runtime status",
		Long: heredoc.Doc(`
			Show substrate runtime status:
			- default driver
			- snapshot fast-path status
			- warm pool size
			- average cold/resume latency
			- observed density
			- per-tenant utilization
		`),
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(statusCmd)
	return cmd
}

func (opts *SubstrateOptions) Run(context.Context, []string) error {
	return nil
}

func (opts *statusOptions) Pre(*cobra.Command, []string) error {
	switch strings.ToLower(strings.TrimSpace(opts.Output)) {
	case "table", "json", "yaml", "list":
		opts.Output = strings.ToLower(strings.TrimSpace(opts.Output))
		return nil
	default:
		return fmt.Errorf("invalid output format: %s", opts.Output)
	}
}

func (opts *statusOptions) Run(ctx context.Context, _ []string) error {
	response := controlplaneapi.SubstrateStatusResponse{}
	if controlplaneapi.Enabled(ctx) {
		client, err := controlplaneapi.NewClientFromContext(ctx)
		if err != nil {
			return err
		}
		status, err := client.SubstrateStatus(ctx)
		if err != nil {
			return err
		}
		response = *status
	} else {
		response = localSubstrateFallback(ctx)
	}

	if opts.Output == "json" {
		encoder := json.NewEncoder(iostreams.G(ctx).Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(response)
	}

	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithOutputFormatFromString(opts.Output),
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
	)
	if err != nil {
		return err
	}

	table.AddField("FIELD", nil)
	table.AddField("VALUE", nil)
	table.EndRow()

	rows := [][2]string{
		{"driver_default", response.DriverDefault},
		{"snapshot_fast_path_enabled", fmt.Sprintf("%t", response.SnapshotFastPath)},
		{"warm_pool_size", fmt.Sprintf("%d", response.WarmPoolSize)},
		{"average_cold_boot_millis", fmt.Sprintf("%.3f", response.AverageColdBootMillis)},
		{"average_resume_millis", fmt.Sprintf("%.3f", response.AverageResumeMillis)},
		{"observed_density", fmt.Sprintf("%.3f", response.ObservedDensity)},
		{"theoretical_density", fmt.Sprintf("%.3f", response.TheoreticalDensity)},
	}

	for _, row := range rows {
		table.AddField(row[0], nil)
		table.AddField(row[1], nil)
		table.EndRow()
	}

	if len(response.DriverOverheadAverages) > 0 {
		drivers := make([]string, 0, len(response.DriverOverheadAverages))
		for driver := range response.DriverOverheadAverages {
			drivers = append(drivers, driver)
		}
		sort.Strings(drivers)
		for _, driver := range drivers {
			table.AddField("driver_overhead_avg_bytes."+driver, nil)
			table.AddField(fmt.Sprintf("%d", response.DriverOverheadAverages[driver]), nil)
			table.EndRow()
		}
	}

	for _, tenant := range response.PerTenantUtilization {
		key := "tenant." + tenant.Tenant
		value := fmt.Sprintf("instances=%d cpu_milli=%d memory_bytes=%d actual_rss_bytes=%d host_overhead_bytes=%d",
			tenant.Instances,
			tenant.CPUMilli,
			tenant.MemoryBytes,
			tenant.ActualRSS,
			tenant.HostOverhead,
		)
		table.AddField(key, nil)
		table.AddField(value, nil)
		table.EndRow()
	}

	return table.Render(iostreams.G(ctx).Out)
}

func localSubstrateFallback(ctx context.Context) controlplaneapi.SubstrateStatusResponse {
	driver := "unknown"
	if platform, _, err := mplatform.Detect(ctx); err == nil {
		switch platform {
		case mplatform.PlatformFirecracker:
			driver = "firecracker"
		case mplatform.PlatformQEMU:
			driver = "qemu"
		default:
			driver = platform.String()
		}
	}

	snapshotFastPath := true
	if raw := strings.TrimSpace(strings.ToLower(os.Getenv("UNIKCTL_SNAPSHOT_FAST_PATH"))); raw != "" {
		snapshotFastPath = !(raw == "0" || raw == "false" || raw == "no" || raw == "off")
	}

	warmPoolSize := 0
	if raw := strings.TrimSpace(os.Getenv("UNIKCTL_WARM_POOL_SIZE")); raw != "" {
		fmt.Sscanf(raw, "%d", &warmPoolSize)
	}

	return controlplaneapi.SubstrateStatusResponse{
		DriverDefault:        driver,
		SnapshotFastPath:     snapshotFastPath,
		WarmPoolSize:         warmPoolSize,
		AverageColdBootMillis: 0,
		AverageResumeMillis:  0,
		ObservedDensity:      0,
		TheoreticalDensity:   0,
		PerTenantUtilization: []controlplaneapi.TenantUtilization{},
	}
}

