// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package doctor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
)

type DoctorOptions struct{}

type checkResult struct {
	Name   string
	Status string
	Detail string
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&DoctorOptions{}, cobra.Command{
		Short: "Run local environment checks",
		Use:   "doctor",
		Args:  cobra.NoArgs,
		Long:  "Run local host checks for deploy prerequisites (qemu/kvm/network/control-plane/runtime tooling).",
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *DoctorOptions) Run(ctx context.Context, _ []string) error {
	results := []checkResult{
		checkQemu(ctx),
		checkKVM(),
		checkNetwork(),
		checkRuntimeTooling(),
		checkControlPlane(ctx),
	}

	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
	)
	if err != nil {
		return err
	}

	cs := iostreams.G(ctx).ColorScheme()
	table.AddField("CHECK", cs.Bold)
	table.AddField("STATUS", cs.Bold)
	table.AddField("DETAILS", cs.Bold)
	table.EndRow()

	hasFailure := false
	for _, result := range results {
		color := statusColor(result.Status)
		if result.Status == "FAIL" {
			hasFailure = true
		}

		table.AddField(result.Name, nil)
		table.AddField(result.Status, color)
		table.AddField(result.Detail, nil)
		table.EndRow()
	}

	if err := table.Render(iostreams.G(ctx).Out); err != nil {
		return err
	}

	if hasFailure {
		return fmt.Errorf("doctor checks failed")
	}

	return nil
}

func checkQemu(ctx context.Context) checkResult {
	qemuBin := strings.TrimSpace(config.G[config.KraftKit](ctx).Qemu)
	if qemuBin != "" {
		if _, err := exec.LookPath(qemuBin); err == nil {
			return checkResult{Name: "qemu", Status: "PASS", Detail: fmt.Sprintf("found %s", qemuBin)}
		}
		return checkResult{Name: "qemu", Status: "FAIL", Detail: fmt.Sprintf("configured binary not found: %s", qemuBin)}
	}

	for _, candidate := range []string{"qemu-system-x86_64", "qemu-system-aarch64", "qemu"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return checkResult{Name: "qemu", Status: "PASS", Detail: fmt.Sprintf("found %s", path)}
		}
	}

	return checkResult{Name: "qemu", Status: "FAIL", Detail: "qemu executable not found in PATH"}
}

func checkKVM() checkResult {
	if runtime.GOOS != "linux" {
		return checkResult{Name: "kvm", Status: "WARN", Detail: "KVM check is only applicable on Linux hosts"}
	}

	if _, err := os.Stat("/dev/kvm"); err != nil {
		return checkResult{Name: "kvm", Status: "WARN", Detail: "/dev/kvm is unavailable (hardware acceleration may be disabled)"}
	}

	file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return checkResult{Name: "kvm", Status: "WARN", Detail: fmt.Sprintf("/dev/kvm exists but is not accessible: %v", err)}
	}
	_ = file.Close()

	return checkResult{Name: "kvm", Status: "PASS", Detail: "/dev/kvm is available"}
}

func checkNetwork() checkResult {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return checkResult{Name: "network", Status: "FAIL", Detail: fmt.Sprintf("cannot bind loopback port: %v", err)}
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return checkResult{Name: "network", Status: "PASS", Detail: fmt.Sprintf("loopback bind works (%s)", address)}
}

func checkRuntimeTooling() checkResult {
	found := []string{}
	for _, candidate := range []string{"node", "python", "go", "rustc"} {
		if path, err := exec.LookPath(candidate); err == nil {
			found = append(found, fmt.Sprintf("%s=%s", candidate, path))
		}
	}

	if len(found) == 0 {
		return checkResult{Name: "runtime-tooling", Status: "WARN", Detail: "no language runtimes found in PATH"}
	}

	return checkResult{Name: "runtime-tooling", Status: "PASS", Detail: strings.Join(found, ", ")}
}

func checkControlPlane(ctx context.Context) checkResult {
	endpoint := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_URL"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(config.G[config.KraftKit](ctx).ControlPlane.URL)
	}
	if endpoint == "" {
		return checkResult{Name: "control-plane", Status: "WARN", Detail: "UNIKCTL_CONTROL_PLANE_URL is not configured"}
	}

	healthURL := strings.TrimRight(endpoint, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return checkResult{Name: "control-plane", Status: "FAIL", Detail: fmt.Sprintf("invalid URL: %v", err)}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return checkResult{Name: "control-plane", Status: "FAIL", Detail: fmt.Sprintf("health check failed: %v", err)}
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return checkResult{Name: "control-plane", Status: "FAIL", Detail: fmt.Sprintf("health returned %s", res.Status)}
	}

	return checkResult{Name: "control-plane", Status: "PASS", Detail: fmt.Sprintf("reachable at %s", endpoint)}
}

func statusColor(status string) func(string) string {
	switch status {
	case "PASS":
		return iostreams.Green
	case "WARN":
		return iostreams.Yellow
	case "FAIL":
		return iostreams.Red
	default:
		return nil
	}
}
