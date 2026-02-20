// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package bench

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
)

type BenchOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&BenchOptions{}, cobra.Command{
		Short: "Run benchmark helpers",
		Use:   "bench",
		Args:  cobra.NoArgs,
		Long:  "Benchmark helpers for density planning and boot/resume latency.",
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(newDensityCmd())
	cmd.AddCommand(newBootCmd())
	return cmd
}

func (opts *BenchOptions) Run(context.Context, []string) error {
	return nil
}

type densityOptions struct {
	NodeMemory       string `long:"node-memory" usage:"Total node memory quantity" default:"16Gi"`
	NodeCPU          string `long:"node-cpu" usage:"Total node CPU quantity" default:"8"`
	InstanceMemory   string `long:"instance-memory" usage:"Per-instance requested memory" default:"64Mi"`
	InstanceCPU      string `long:"instance-cpu" usage:"Per-instance requested CPU" default:"1"`
	OverheadMemory   string `long:"overhead-memory" usage:"Per-instance host overhead memory (used as fallback when observed overhead is unavailable)" default:"16Mi"`
	OverheadCPUMilli int64  `long:"overhead-cpu-milli" usage:"Per-instance host overhead CPU in millicores" default:"50"`
	SafetyMarginPct  int64  `long:"safety-margin-pct" usage:"Safety margin percent subtracted from total capacity" default:"15"`
	ControlPlaneURL  string `long:"control-plane-url" usage:"Control-plane endpoint (optional, used for observed density/overhead data)"`
	Token            string `long:"token" usage:"Bearer token for control-plane metrics/status endpoints"`
	TLSInsecure      bool   `long:"tls-insecure-skip-verify" usage:"Skip TLS verification when querying metrics/status"`
	Output           string `long:"output" short:"o" usage:"Output format: table,json,yaml,list" default:"table"`
}

func newDensityCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&densityOptions{}, cobra.Command{
		Use:   "density",
		Short: "Estimate safe instance density on a node",
		Long: heredoc.Doc(`
			Calculate the theoretical safe max instance count from requested CPU/memory
			and per-instance hypervisor overhead.
		`),
		Example: heredoc.Doc(`
			unikctl bench density
			unikctl bench density --node-memory 64Gi --node-cpu 32 --instance-memory 256Mi --instance-cpu 500m
		`),
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func (opts *densityOptions) Pre(cmd *cobra.Command, _ []string) error {
	switch strings.ToLower(strings.TrimSpace(opts.Output)) {
	case "table", "json", "yaml", "list":
		opts.Output = strings.ToLower(strings.TrimSpace(opts.Output))
	default:
		return fmt.Errorf("invalid output format: %s", opts.Output)
	}

	if opts.SafetyMarginPct < 0 {
		opts.SafetyMarginPct = 0
	}
	if opts.SafetyMarginPct > 90 {
		opts.SafetyMarginPct = 90
	}

	if strings.TrimSpace(opts.ControlPlaneURL) == "" {
		opts.ControlPlaneURL = strings.TrimSpace(config.G[config.KraftKit](cmd.Context()).ControlPlane.URL)
	}
	if strings.TrimSpace(opts.ControlPlaneURL) == "" {
		opts.ControlPlaneURL = strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_URL"))
	}
	if strings.TrimSpace(opts.Token) == "" {
		opts.Token = strings.TrimSpace(config.G[config.KraftKit](cmd.Context()).ControlPlane.Token)
	}
	if strings.TrimSpace(opts.Token) == "" {
		opts.Token = strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN"))
	}

	return nil
}

func (opts *densityOptions) Run(ctx context.Context, _ []string) error {
	nodeMem, err := parsePositiveBytes(opts.NodeMemory)
	if err != nil {
		return fmt.Errorf("invalid --node-memory: %w", err)
	}
	nodeCPU, err := parsePositiveMilliCPU(opts.NodeCPU)
	if err != nil {
		return fmt.Errorf("invalid --node-cpu: %w", err)
	}
	instMem, err := parsePositiveBytes(opts.InstanceMemory)
	if err != nil {
		return fmt.Errorf("invalid --instance-memory: %w", err)
	}
	instCPU, err := parsePositiveMilliCPU(opts.InstanceCPU)
	if err != nil {
		return fmt.Errorf("invalid --instance-cpu: %w", err)
	}
	overheadMem, err := parsePositiveBytes(opts.OverheadMemory)
	if err != nil {
		return fmt.Errorf("invalid --overhead-memory: %w", err)
	}

	overheadSource := "flag"
	observedInstances := int64(0)
	observedRSSBytes := int64(0)
	observedOverheadBytes := int64(0)
	if strings.TrimSpace(opts.ControlPlaneURL) != "" {
		if metricsBody, metricsErr := fetchMetrics(opts.ControlPlaneURL, opts.Token, opts.TLSInsecure); metricsErr == nil {
			values := parsePrometheusValues(metricsBody)
			if v, ok := values["unikctl_control_plane_actual_rss_bytes_total"]; ok && v > 0 {
				observedRSSBytes = int64(v)
			}
			if v, ok := values["unikctl_control_plane_host_overhead_bytes_total"]; ok && v > 0 {
				observedOverheadBytes = int64(v)
			}
		}

		client, clientErr := controlplaneapi.NewClient(opts.ControlPlaneURL, controlplaneapi.ClientOptions{
			AuthToken:   strings.TrimSpace(opts.Token),
			TenantID:    strings.TrimSpace(os.Getenv("UNIKCTL_TENANT")),
			TLSInsecure: opts.TLSInsecure,
			Timeout:     10 * time.Second,
		})
		if clientErr == nil {
			if status, statusErr := client.Status(ctx); statusErr == nil {
				for _, machine := range status.Machines {
					if strings.EqualFold(strings.TrimSpace(machine.State), "running") {
						observedInstances++
					}
				}
			}
		}
	}

	if observedInstances > 0 && observedOverheadBytes > 0 {
		overheadMem = maxInt64(observedOverheadBytes/observedInstances, overheadMem)
		overheadSource = "observed"
	}

	safetyMemBytes := int64(float64(nodeMem) * (float64(100-opts.SafetyMarginPct) / 100.0))
	safetyCPUMilli := int64(float64(nodeCPU) * (float64(100-opts.SafetyMarginPct) / 100.0))
	if safetyMemBytes <= 0 {
		safetyMemBytes = nodeMem
	}
	if safetyCPUMilli <= 0 {
		safetyCPUMilli = nodeCPU
	}

	totalPerInstanceMem := instMem + overheadMem
	totalPerInstanceCPU := instCPU + maxInt64(opts.OverheadCPUMilli, 0)
	if totalPerInstanceMem <= 0 || totalPerInstanceCPU <= 0 {
		return fmt.Errorf("total per-instance resources must be greater than zero")
	}

	memCap := safetyMemBytes / totalPerInstanceMem
	cpuCap := safetyCPUMilli / totalPerInstanceCPU
	theoreticalMax := int64(math.Min(float64(memCap), float64(cpuCap)))
	observedDensity := observedInstances
	if observedDensity < 0 {
		observedDensity = 0
	}

	safeMax := theoreticalMax
	if safeMax < 0 {
		safeMax = 0
	}

	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithOutputFormatFromString(opts.Output),
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
	)
	if err != nil {
		return err
	}

	rows := []struct {
		Key   string
		Value string
	}{
		{"node_memory_bytes", fmt.Sprintf("%d", nodeMem)},
		{"node_cpu_milli", fmt.Sprintf("%d", nodeCPU)},
		{"safety_margin_pct", fmt.Sprintf("%d", opts.SafetyMarginPct)},
		{"effective_node_memory_bytes", fmt.Sprintf("%d", safetyMemBytes)},
		{"effective_node_cpu_milli", fmt.Sprintf("%d", safetyCPUMilli)},
		{"instance_memory_bytes", fmt.Sprintf("%d", instMem)},
		{"instance_cpu_milli", fmt.Sprintf("%d", instCPU)},
		{"overhead_memory_bytes", fmt.Sprintf("%d", overheadMem)},
		{"overhead_source", overheadSource},
		{"overhead_cpu_milli", fmt.Sprintf("%d", opts.OverheadCPUMilli)},
		{"effective_memory_per_instance_bytes", fmt.Sprintf("%d", totalPerInstanceMem)},
		{"effective_cpu_per_instance_milli", fmt.Sprintf("%d", totalPerInstanceCPU)},
		{"theoretical_density", fmt.Sprintf("%d", theoreticalMax)},
		{"observed_density", fmt.Sprintf("%d", observedDensity)},
		{"safe_max_instances", fmt.Sprintf("%d", safeMax)},
		{"observed_rss_bytes_total", fmt.Sprintf("%d", observedRSSBytes)},
		{"observed_overhead_bytes_total", fmt.Sprintf("%d", observedOverheadBytes)},
	}

	table.AddField("FIELD", nil)
	table.AddField("VALUE", nil)
	table.EndRow()
	for _, row := range rows {
		table.AddField(row.Key, nil)
		table.AddField(row.Value, nil)
		table.EndRow()
	}

	return table.Render(iostreams.G(ctx).Out)
}

type bootOptions struct {
	ControlPlaneURL string `long:"control-plane-url" usage:"Control-plane endpoint (defaults to config/env)"`
	Token           string `long:"token" usage:"Bearer token for control-plane metrics endpoint"`
	TLSInsecure     bool   `long:"tls-insecure-skip-verify" usage:"Skip TLS verification when querying metrics"`
	Output          string `long:"output" short:"o" usage:"Output format: table,json,yaml,list" default:"table"`
}

func newBootCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&bootOptions{}, cobra.Command{
		Use:   "boot",
		Short: "Show cold/resume/pause/snapshot latency metrics",
		Long: heredoc.Doc(`
			Reads boot lifecycle latency instrumentation from the control-plane metrics endpoint.
			Includes cold deploy latency and warm-pool snapshot/resume latencies.
		`),
		Example: heredoc.Doc(`
			unikctl bench boot
			unikctl bench boot --control-plane-url https://127.0.0.1:7689
		`),
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func (opts *bootOptions) Pre(cmd *cobra.Command, _ []string) error {
	switch strings.ToLower(strings.TrimSpace(opts.Output)) {
	case "table", "json", "yaml", "list":
		opts.Output = strings.ToLower(strings.TrimSpace(opts.Output))
	default:
		return fmt.Errorf("invalid output format: %s", opts.Output)
	}

	if strings.TrimSpace(opts.ControlPlaneURL) == "" {
		opts.ControlPlaneURL = strings.TrimSpace(config.G[config.KraftKit](cmd.Context()).ControlPlane.URL)
	}
	if strings.TrimSpace(opts.ControlPlaneURL) == "" {
		opts.ControlPlaneURL = strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_URL"))
	}
	if strings.TrimSpace(opts.ControlPlaneURL) == "" {
		opts.ControlPlaneURL = "https://127.0.0.1:7689"
	}

	if strings.TrimSpace(opts.Token) == "" {
		opts.Token = strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_TOKEN"))
	}

	return nil
}

func (opts *bootOptions) Run(ctx context.Context, _ []string) error {
	metricsBody, err := fetchMetrics(opts.ControlPlaneURL, opts.Token, opts.TLSInsecure)
	if err != nil {
		return err
	}

	values := parsePrometheusValues(metricsBody)
	rows := []struct {
		Key   string
		Value string
	}{
		{"deploy_cold_boot_ms_avg", formatMetric(values, "unikctl_control_plane_deploy_latency_ms_avg")},
		{"warm_resume_ms_avg", formatMetric(values, "unikctl_control_plane_warm_resume_latency_ms_avg")},
		{"warm_pause_ms_avg", formatMetric(values, "unikctl_control_plane_warm_pause_latency_ms_avg")},
		{"snapshot_create_ms_avg", formatMetric(values, "unikctl_control_plane_snapshot_latency_ms_avg")},
		{"warm_gc_total", formatMetric(values, "unikctl_control_plane_warm_gc_total")},
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
	for _, row := range rows {
		table.AddField(row.Key, nil)
		table.AddField(row.Value, nil)
		table.EndRow()
	}
	return table.Render(iostreams.G(ctx).Out)
}

func fetchMetrics(endpoint, token string, tlsInsecure bool) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("control plane URL is required")
	}

	endpoint = strings.TrimRight(endpoint, "/") + "/v1/metrics"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecure}, //nolint:gosec
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("metrics endpoint returned status %d", response.StatusCode)
	}

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func parsePrometheusValues(raw string) map[string]float64 {
	values := map[string]float64{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		metricName := strings.TrimSpace(fields[0])
		valueRaw := strings.TrimSpace(fields[len(fields)-1])
		value, err := strconv.ParseFloat(valueRaw, 64)
		if err != nil {
			continue
		}
		values[metricName] = value
	}
	return values
}

func formatMetric(values map[string]float64, key string) string {
	value, ok := values[key]
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%.3f", value)
}

func parsePositiveBytes(value string) (int64, error) {
	qty, err := resource.ParseQuantity(strings.TrimSpace(value))
	if err != nil {
		return 0, err
	}
	if qty.Value() <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return qty.Value(), nil
}

func parsePositiveMilliCPU(value string) (int64, error) {
	qty, err := resource.ParseQuantity(strings.TrimSpace(value))
	if err != nil {
		return 0, err
	}
	if qty.MilliValue() <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return qty.MilliValue(), nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
