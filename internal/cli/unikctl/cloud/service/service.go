// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package service

import (
	"context"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/internal/cli/unikctl/cloud/service/create"
	"unikctl.sh/internal/cli/unikctl/cloud/service/drain"
	"unikctl.sh/internal/cli/unikctl/cloud/service/get"
	"unikctl.sh/internal/cli/unikctl/cloud/service/list"
	"unikctl.sh/internal/cli/unikctl/cloud/service/logs"
	"unikctl.sh/internal/cli/unikctl/cloud/service/remove"

	"unikctl.sh/cmdfactory"
)

type ServiceOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ServiceOptions{}, cobra.Command{
		Short:   "Manage services on KraftCloud",
		Use:     "service SUBCOMMAND",
		Aliases: []string{"services", "svc"},
		Long:    "Manage services on KraftCloud.",
		Example: heredoc.Doc(`
			# List services in your account.
			$ unikctl cloud service list
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "kraftcloud-service",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(create.NewCmd())
	cmd.AddCommand(drain.NewCmd())
	cmd.AddCommand(list.NewCmd())
	cmd.AddCommand(get.NewCmd())
	cmd.AddCommand(logs.NewCmd())
	cmd.AddCommand(remove.NewCmd())

	return cmd
}

func (opts *ServiceOptions) Run(_ context.Context, _ []string) error {
	return pflag.ErrHelp
}
