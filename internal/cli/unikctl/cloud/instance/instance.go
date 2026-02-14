// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package instance

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/cmdfactory"

	"unikctl.sh/internal/cli/unikctl/cloud/instance/create"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/get"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/list"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/logs"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/remove"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/restart"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/start"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/stop"
	"unikctl.sh/internal/cli/unikctl/cloud/instance/template"
)

type InstanceOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&InstanceOptions{}, cobra.Command{
		Short:   "Manage instances",
		Use:     "instance SUBCOMMAND",
		Aliases: []string{"inst", "instances", "vm", "vms"},
		Long:    "Manage instances on Unikraft Cloud.",
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "kraftcloud-instance",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(create.NewCmd())
	cmd.AddCommand(list.NewCmd())
	cmd.AddCommand(logs.NewCmd())
	cmd.AddCommand(remove.NewCmd())
	cmd.AddCommand(restart.NewCmd())
	cmd.AddCommand(start.NewCmd())
	cmd.AddCommand(get.NewCmd())
	cmd.AddCommand(stop.NewCmd())

	cmd.AddGroup(&cobra.Group{ID: "kraftcloud-instance-template", Title: "TEMPLATE COMMANDS"})
	cmd.AddCommand(template.NewCmd())

	return cmd
}

func (opts *InstanceOptions) Run(_ context.Context, _ []string) error {
	return pflag.ErrHelp
}
