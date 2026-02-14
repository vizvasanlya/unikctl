// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package node

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
)

type NodeOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&NodeOptions{}, cobra.Command{
		Use:   "node",
		Short: "Manage control-plane nodes",
		Args:  cobra.NoArgs,
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newCordonCmd())
	cmd.AddCommand(newUncordonCmd())
	cmd.AddCommand(newDrainCmd())

	return cmd
}

type nodeActionOptions struct {
	action string
}

func newListCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&NodeOptions{}, cobra.Command{
		Use:   "list",
		Short: "List registered nodes",
		Args:  cobra.NoArgs,
		Aliases: []string{
			"ls",
		},
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func (opts *NodeOptions) RunList(ctx context.Context) error {
	client, err := controlplaneapi.NewClientFromContext(ctx)
	if err != nil {
		return err
	}

	status, err := client.Status(ctx)
	if err != nil {
		return err
	}

	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
	)
	if err != nil {
		return err
	}
	cs := iostreams.G(ctx).ColorScheme()
	table.AddField("NAME", cs.Bold)
	table.AddField("STATE", cs.Bold)
	table.AddField("ADDRESS", cs.Bold)
	table.AddField("CPU(m)", cs.Bold)
	table.AddField("MEM(bytes)", cs.Bold)
	table.AddField("MACHINES", cs.Bold)
	table.AddField("LABELS", cs.Bold)
	table.EndRow()

	for _, node := range status.Nodes {
		labelPairs := make([]string, 0, len(node.Labels))
		for key, value := range node.Labels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", key, value))
		}
		table.AddField(node.Name, nil)
		table.AddField(node.State, nil)
		table.AddField(firstNonEmpty(node.AgentURL, node.Address), nil)
		table.AddField(fmt.Sprintf("%d", node.CapacityCPUMilli), nil)
		table.AddField(fmt.Sprintf("%d", node.CapacityMemBytes), nil)
		table.AddField(fmt.Sprintf("%d", node.Machines), nil)
		table.AddField(strings.Join(labelPairs, ","), nil)
		table.EndRow()
	}

	return table.Render(iostreams.G(ctx).Out)
}

func newCordonCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&nodeActionOptions{action: "cordon"}, cobra.Command{
		Use:   "cordon NODE",
		Short: "Cordon a node",
		Args:  cobra.ExactArgs(1),
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func newUncordonCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&nodeActionOptions{action: "uncordon"}, cobra.Command{
		Use:   "uncordon NODE",
		Short: "Uncordon a node",
		Args:  cobra.ExactArgs(1),
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func newDrainCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&nodeActionOptions{action: "drain"}, cobra.Command{
		Use:   "drain NODE",
		Short: "Drain a node and reschedule workloads",
		Args:  cobra.ExactArgs(1),
	})
	if err != nil {
		panic(err)
	}
	return cmd
}

func (opts *nodeActionOptions) Run(ctx context.Context, args []string) error {
	client, err := controlplaneapi.NewClientFromContext(ctx)
	if err != nil {
		return err
	}

	nodeName := strings.TrimSpace(args[0])
	var response *controlplaneapi.NodeActionResponse

	switch opts.action {
	case "cordon":
		response, err = client.CordonNode(ctx, nodeName)
	case "uncordon":
		response, err = client.UncordonNode(ctx, nodeName)
	case "drain":
		response, err = client.DrainNode(ctx, nodeName)
	default:
		return fmt.Errorf("unsupported action: %s", opts.action)
	}
	if err != nil {
		return err
	}

	if response.Migrated > 0 || response.Failed > 0 {
		fmt.Fprintf(iostreams.G(ctx).Out, "%s %s (migrated=%d failed=%d)\n", response.Name, response.State, response.Migrated, response.Failed)
		return nil
	}

	fmt.Fprintf(iostreams.G(ctx).Out, "%s %s\n", response.Name, response.State)
	return nil
}

func (opts *NodeOptions) Run(ctx context.Context, _ []string) error {
	return opts.RunList(ctx)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
