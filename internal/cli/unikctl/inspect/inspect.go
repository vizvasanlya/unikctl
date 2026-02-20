// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
	mplatform "unikctl.sh/machine/platform"
)

type InspectOptions struct {
	Output string `long:"output" short:"o" usage:"Output format: table,json,yaml,list" default:"table"`
}

type inspectRecord struct {
	ID           string    `json:"id,omitempty"`
	Name         string    `json:"name"`
	Node         string    `json:"node,omitempty"`
	State        string    `json:"state"`
	Driver       string    `json:"driver,omitempty"`
	Architecture string    `json:"architecture,omitempty"`
	Kernel       string    `json:"kernel,omitempty"`
	Args         string    `json:"args,omitempty"`
	CPURequest   string    `json:"cpu_request,omitempty"`
	MemoryRequest string   `json:"memory_request,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	Ports        string    `json:"ports,omitempty"`
	SnapshotState string   `json:"snapshot_state,omitempty"`
	SnapshotPath string    `json:"snapshot_path,omitempty"`
	SnapshotMem  string    `json:"snapshot_mem,omitempty"`
	SnapshotMeta string    `json:"snapshot_meta,omitempty"`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&InspectOptions{}, cobra.Command{
		Short: "Inspect one deployment in detail",
		Use:   "inspect APP",
		Args:  cobra.ExactArgs(1),
		Long: heredoc.Doc(`
			Show detailed runtime information for one deployment.
			Includes requested resources, runtime driver, and snapshot state.
		`),
		Example: heredoc.Doc(`
			unikctl inspect my-app
			unikctl inspect my-app -o json
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *InspectOptions) Pre(cmd *cobra.Command, _ []string) error {
	allowed := map[string]struct{}{
		"table": {},
		"json":  {},
		"yaml":  {},
		"list":  {},
	}
	value := strings.ToLower(strings.TrimSpace(opts.Output))
	if _, ok := allowed[value]; !ok {
		return fmt.Errorf("invalid output format: %s", opts.Output)
	}
	opts.Output = value
	return nil
}

func (opts *InspectOptions) Run(ctx context.Context, args []string) error {
	target := strings.TrimSpace(args[0])
	if target == "" {
		return fmt.Errorf("app name is required")
	}

	record, err := inspectDeployment(ctx, target)
	if err != nil {
		return err
	}

	switch opts.Output {
	case "json":
		encoder := json.NewEncoder(iostreams.G(ctx).Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(record)
	default:
		return printInspectTable(ctx, record, opts.Output)
	}
}

func inspectDeployment(ctx context.Context, target string) (inspectRecord, error) {
	if controlplaneapi.Enabled(ctx) {
		client, err := controlplaneapi.NewClientFromContext(ctx)
		if err != nil {
			return inspectRecord{}, err
		}

		response, err := client.Inspect(ctx, target)
		if err != nil {
			return inspectRecord{}, err
		}

		return inspectRecord{
			ID:            response.ID,
			Name:          response.Name,
			Node:          response.Node,
			State:         response.State,
			Driver:        response.Driver,
			Architecture:  response.Architecture,
			Kernel:        response.Kernel,
			Args:          response.Args,
			CPURequest:    response.CPURequest,
			MemoryRequest: response.MemoryRequest,
			CreatedAt:     response.CreatedAt,
			Ports:         response.Ports,
			SnapshotState: response.SnapshotState,
			SnapshotPath:  response.SnapshotPath,
			SnapshotMem:   response.SnapshotMem,
			SnapshotMeta:  response.SnapshotMeta,
		}, nil
	}

	controller, err := mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	if err != nil {
		return inspectRecord{}, err
	}

	machines, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return inspectRecord{}, err
	}

	for _, machine := range machines.Items {
		if machine.Name != target && string(machine.UID) != target {
			continue
		}

		snapshotPath, snapshotMem, snapshotMeta := snapshotFields(machine.Status.PlatformConfig)
		snapshotState := "none"
		if snapshotPath != "" || snapshotMem != "" || snapshotMeta != "" {
			snapshotState = "available"
		}

		return inspectRecord{
			ID:            string(machine.UID),
			Name:          machine.Name,
			Node:          "node-local",
			State:         string(machine.Status.State),
			Driver:        machine.Spec.Platform,
			Architecture:  machine.Spec.Architecture,
			Kernel:        machine.Spec.Kernel,
			Args:          strings.Join(machine.Spec.ApplicationArgs, " "),
			CPURequest:    machine.Spec.Resources.Requests.Cpu().String(),
			MemoryRequest: machine.Spec.Resources.Requests.Memory().String(),
			CreatedAt:     machine.ObjectMeta.CreationTimestamp.Time.UTC(),
			Ports:         machine.Spec.Ports.String(),
			SnapshotState: snapshotState,
			SnapshotPath:  snapshotPath,
			SnapshotMem:   snapshotMem,
			SnapshotMeta:  snapshotMeta,
		}, nil
	}

	return inspectRecord{}, fmt.Errorf("deployment not found: %s", target)
}

func snapshotFields(platformConfig any) (string, string, string) {
	if platformConfig == nil {
		return "", "", ""
	}

	raw, err := json.Marshal(platformConfig)
	if err != nil {
		return "", "", ""
	}

	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return "", "", ""
	}

	lookup := func(keys ...string) string {
		for _, key := range keys {
			value, ok := values[key]
			if !ok {
				continue
			}
			text, _ := value.(string)
			text = strings.TrimSpace(text)
			if text != "" {
				return text
			}
		}
		return ""
	}

	return lookup("snapshotPath", "snapshot_path"),
		lookup("snapshotMem", "snapshot_mem"),
		lookup("snapshotMeta", "snapshot_meta")
}

func printInspectTable(ctx context.Context, record inspectRecord, output string) error {
	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithOutputFormatFromString(output),
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
	)
	if err != nil {
		return err
	}

	type row struct {
		key   string
		value string
	}
	rows := []row{
		{key: "name", value: record.Name},
		{key: "id", value: record.ID},
		{key: "node", value: record.Node},
		{key: "state", value: record.State},
		{key: "driver", value: record.Driver},
		{key: "arch", value: record.Architecture},
		{key: "kernel", value: record.Kernel},
		{key: "args", value: record.Args},
		{key: "cpu_request", value: record.CPURequest},
		{key: "memory_request", value: record.MemoryRequest},
		{key: "ports", value: record.Ports},
		{key: "snapshot_state", value: record.SnapshotState},
		{key: "snapshot_path", value: record.SnapshotPath},
		{key: "snapshot_mem", value: record.SnapshotMem},
		{key: "snapshot_meta", value: record.SnapshotMeta},
	}

	if !record.CreatedAt.IsZero() {
		rows = append(rows, row{key: "created_at", value: record.CreatedAt.Format(time.RFC3339)})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key < rows[j].key
	})

	table.AddField("FIELD", nil)
	table.AddField("VALUE", nil)
	table.EndRow()

	for _, item := range rows {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		table.AddField(item.key, nil)
		table.AddField(item.value, nil)
		table.EndRow()
	}

	return table.Render(iostreams.G(ctx).Out)
}
