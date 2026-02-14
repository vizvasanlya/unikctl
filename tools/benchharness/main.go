// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"unikctl.sh/internal/controlplaneapi"
)

type iterationResult struct {
	Iteration       int     `json:"iteration"`
	OperationID     string  `json:"operation_id,omitempty"`
	Machine         string  `json:"machine,omitempty"`
	DeployLatencyMS float64 `json:"deploy_latency_ms"`
	BootTimeMS      float64 `json:"boot_time_ms"`
	Success         bool    `json:"success"`
	Error           string  `json:"error,omitempty"`
}

type benchmarkResult struct {
	TimestampUTC       time.Time         `json:"timestamp_utc"`
	Skipped            bool              `json:"skipped"`
	SkipReason         string            `json:"skip_reason,omitempty"`
	Iterations         int               `json:"iterations"`
	Successful         int               `json:"successful"`
	Failed             int               `json:"failed"`
	FailureRate        float64           `json:"failure_rate"`
	AvgDeployLatencyMS float64           `json:"avg_deploy_latency_ms"`
	AvgBootTimeMS      float64           `json:"avg_boot_time_ms"`
	Results            []iterationResult `json:"results"`
	MetricsText        string            `json:"metrics_text,omitempty"`
}

func main() {
	var (
		binaryPath          = flag.String("binary", "./unikctl", "path to unikctl binary")
		iterations          = flag.Int("iterations", 3, "number of benchmark deploy iterations")
		outputPath          = flag.String("output", "benchmark-results.json", "output JSON report path")
		metricsPath         = flag.String("metrics-output", "benchmark-metrics.txt", "output control-plane metrics text path")
		controlPlaneListen  = flag.String("control-plane-listen", "127.0.0.1:7869", "control-plane listen address")
		timeoutPerIteration = flag.Duration("timeout", 90*time.Second, "per-iteration timeout")
	)
	flag.Parse()

	result := benchmarkResult{
		TimestampUTC: time.Now().UTC(),
		Iterations:   max(*iterations, 1),
		Results:      []iterationResult{},
	}

	if !hasQEMU() {
		result.Skipped = true
		result.SkipReason = "qemu binary not found in PATH"
		mustWriteOutputs(*outputPath, *metricsPath, result)
		fmt.Printf("benchmark skipped: %s\n", result.SkipReason)
		return
	}

	binAbs, err := filepath.Abs(*binaryPath)
	if err != nil {
		fatalResult(err, *outputPath, *metricsPath, result)
	}
	if _, err := os.Stat(binAbs); err != nil {
		fatalResult(fmt.Errorf("unikctl binary not found at %s: %w", binAbs, err), *outputPath, *metricsPath, result)
	}

	workDir, err := os.MkdirTemp("", "unikctl-bench-*")
	if err != nil {
		fatalResult(err, *outputPath, *metricsPath, result)
	}
	defer os.RemoveAll(workDir)

	appDir := filepath.Join(workDir, "app")
	if err := prepareGoBenchmarkApp(appDir); err != nil {
		fatalResult(err, *outputPath, *metricsPath, result)
	}

	runtimeDir := filepath.Join(workDir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		fatalResult(err, *outputPath, *metricsPath, result)
	}

	controlPlaneURL := "http://" + *controlPlaneListen
	controlPlaneToken := "bench-token"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlPlaneCmd := exec.CommandContext(ctx, binAbs, "control-plane")
	controlPlaneCmd.Env = append(os.Environ(),
		"UNIKCTL_RUNTIME_DIR="+runtimeDir,
		"UNIKCTL_CONTROL_PLANE_LISTEN="+*controlPlaneListen,
		"UNIKCTL_CONTROL_PLANE_TOKEN="+controlPlaneToken,
	)
	controlPlaneLogs := &bytes.Buffer{}
	controlPlaneCmd.Stdout = controlPlaneLogs
	controlPlaneCmd.Stderr = controlPlaneLogs

	if err := controlPlaneCmd.Start(); err != nil {
		fatalResult(fmt.Errorf("starting control-plane: %w", err), *outputPath, *metricsPath, result)
	}
	defer func() {
		cancel()
		_ = controlPlaneCmd.Process.Kill()
		_, _ = controlPlaneLogs.WriteString("\n")
	}()

	if err := waitForHealth(controlPlaneURL, controlPlaneToken, 20*time.Second); err != nil {
		fatalResult(fmt.Errorf("control-plane did not become healthy: %w\n%s", err, controlPlaneLogs.String()), *outputPath, *metricsPath, result)
	}

	client, err := controlplaneapi.NewClient(controlPlaneURL, controlplaneapi.ClientOptions{
		AuthToken: controlPlaneToken,
		Timeout:   20 * time.Second,
	})
	if err != nil {
		fatalResult(err, *outputPath, *metricsPath, result)
	}

	for i := 0; i < result.Iterations; i++ {
		iter := iterationResult{
			Iteration: i + 1,
			Success:   false,
		}

		startedAt := time.Now()
		opID, deployErr := runDeploy(binAbs, appDir, runtimeDir, controlPlaneURL, controlPlaneToken)
		iter.OperationID = opID
		if deployErr != nil {
			iter.Error = deployErr.Error()
			result.Results = append(result.Results, iter)
			result.Failed++
			continue
		}

		operationLatency, bootLatency, machineName, waitErr := waitForOperationAndBoot(client, opID, *timeoutPerIteration)
		iter.Machine = machineName
		iter.DeployLatencyMS = operationLatency.Seconds() * 1000
		iter.BootTimeMS = bootLatency.Seconds() * 1000
		if waitErr != nil {
			iter.Error = waitErr.Error()
			result.Results = append(result.Results, iter)
			result.Failed++
			_ = destroyAll(client)
			continue
		}

		iter.Success = true
		result.Successful++
		result.Results = append(result.Results, iter)

		_ = destroyAll(client)
		_ = waitForNoMachines(client, 30*time.Second)

		_ = startedAt
	}

	result.Failed = result.Iterations - result.Successful
	if result.Iterations > 0 {
		result.FailureRate = float64(result.Failed) / float64(result.Iterations)
	}
	result.AvgDeployLatencyMS = averageMetric(result.Results, func(item iterationResult) float64 {
		return item.DeployLatencyMS
	})
	result.AvgBootTimeMS = averageMetric(result.Results, func(item iterationResult) float64 {
		return item.BootTimeMS
	})

	metricsText, err := fetchMetrics(controlPlaneURL, controlPlaneToken)
	if err == nil {
		result.MetricsText = metricsText
	}

	mustWriteOutputs(*outputPath, *metricsPath, result)
	fmt.Printf("benchmark complete: success=%d failed=%d avg_deploy_ms=%.2f avg_boot_ms=%.2f\n", result.Successful, result.Failed, result.AvgDeployLatencyMS, result.AvgBootTimeMS)
}

func hasQEMU() bool {
	for _, binary := range []string{"qemu-system-x86_64", "qemu-system-aarch64", "qemu"} {
		if _, err := exec.LookPath(binary); err == nil {
			return true
		}
	}
	return false
}

func prepareGoBenchmarkApp(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	goMod := "module benchapp\n\ngo 1.21\n"
	mainGo := `package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	fmt.Println("benchmark app listening on :8080")
	_ = http.ListenAndServe(":8080", nil)
}
`

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return err
	}
	// Release mode requires lock-like artifact for deterministic builds in this fork.
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(""), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		return err
	}
	return nil
}

func waitForHealth(baseURL, token string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/healthz", nil)
		if strings.TrimSpace(token) != "" {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
		}

		res, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode/100 == 2 {
				return nil
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for /healthz")
}

func runDeploy(binaryPath, appDir, runtimeDir, controlPlaneURL, token string) (string, error) {
	cmd := exec.Command(binaryPath, "deploy", appDir)
	cmd.Env = append(os.Environ(),
		"UNIKCTL_RUNTIME_DIR="+runtimeDir,
		"UNIKCTL_CONTROL_PLANE_URL="+controlPlaneURL,
		"UNIKCTL_CONTROL_PLANE_TOKEN="+token,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("deploy command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}

	opID := parseOperationID(string(output))
	if opID == "" {
		return "", fmt.Errorf("could not parse operation id from deploy output: %s", strings.TrimSpace(string(output)))
	}
	return opID, nil
}

var operationIDPattern = regexp.MustCompile(`operation:\s*([^\s]+)`)

func parseOperationID(output string) string {
	matches := operationIDPattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func waitForOperationAndBoot(client *controlplaneapi.Client, operationID string, timeout time.Duration) (time.Duration, time.Duration, string, error) {
	startedAt := time.Now()
	deadline := startedAt.Add(timeout)
	operationDoneAt := time.Time{}
	bootDoneAt := time.Time{}
	machineName := ""

	for time.Now().Before(deadline) {
		status, err := client.Status(context.Background())
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, operation := range status.Operations {
			if operation.ID != operationID {
				continue
			}

			if machineName == "" {
				machineName = strings.TrimSpace(operation.Target)
			}

			state := strings.ToLower(strings.TrimSpace(operation.State))
			if state == "failed" {
				return durationOrZero(startedAt, operationDoneAt), durationOrZero(startedAt, bootDoneAt), machineName, errors.New(firstNonEmpty(operation.Error, operation.Message, "operation failed"))
			}

			if state == "submitted" || state == "succeeded" {
				if operationDoneAt.IsZero() {
					operationDoneAt = time.Now()
				}
			}
		}

		for _, machine := range status.Machines {
			if machineName != "" && machine.Name != machineName {
				continue
			}

			state := strings.ToLower(strings.TrimSpace(machine.State))
			if state == "running" || state == "exited" {
				if machineName == "" {
					machineName = machine.Name
				}
				if bootDoneAt.IsZero() {
					bootDoneAt = time.Now()
				}
				break
			}
		}

		if !operationDoneAt.IsZero() && !bootDoneAt.IsZero() {
			return operationDoneAt.Sub(startedAt), bootDoneAt.Sub(startedAt), machineName, nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return durationOrZero(startedAt, operationDoneAt), durationOrZero(startedAt, bootDoneAt), machineName, fmt.Errorf("timeout waiting for operation %s", operationID)
}

func destroyAll(client *controlplaneapi.Client) error {
	_, err := client.Destroy(context.Background(), controlplaneapi.DestroyRequest{
		All: true,
	})
	return err
}

func waitForNoMachines(client *controlplaneapi.Client, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := client.Status(context.Background())
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if len(status.Machines) == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for machines to terminate")
}

func fetchMetrics(baseURL, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/v1/metrics", nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}

	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("metrics request failed: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}

	return string(body), nil
}

func mustWriteOutputs(jsonPath, metricsPath string, result benchmarkResult) {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
		panic(err)
	}

	metrics := result.MetricsText
	if metrics == "" {
		metrics = "# no metrics available\n"
	}

	if err := os.WriteFile(metricsPath, []byte(metrics), 0o644); err != nil {
		panic(err)
	}
}

func fatalResult(err error, outputPath, metricsPath string, result benchmarkResult) {
	result.Skipped = true
	result.SkipReason = err.Error()
	mustWriteOutputs(outputPath, metricsPath, result)
	fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
	os.Exit(1)
}

func averageMetric(items []iterationResult, extract func(iterationResult) float64) float64 {
	sum := 0.0
	count := 0
	for _, item := range items {
		if !item.Success {
			continue
		}
		value := extract(item)
		if value <= 0 {
			continue
		}
		sum += value
		count++
	}

	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func durationOrZero(startedAt, endedAt time.Time) time.Duration {
	if endedAt.IsZero() {
		return 0
	}
	if endedAt.Before(startedAt) {
		return 0
	}
	return endedAt.Sub(startedAt)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func max(values ...int) int {
	maxValue := 0
	for _, value := range values {
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}
