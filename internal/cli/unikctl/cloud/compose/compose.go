// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package compose

import (
	"context"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/internal/cli/unikctl/cloud/compose/build"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/create"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/down"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/list"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/logs"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/ps"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/push"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/start"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/stop"
	"unikctl.sh/internal/cli/unikctl/cloud/compose/up"

	"unikctl.sh/cmdfactory"
)

type ComposeOptions struct {
	Composefile string `long:"file" usage:"Set the Compose file."`
	EnvFile     string `long:"env-file" usage:"Set the environment file."`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ComposeOptions{}, cobra.Command{
		Short:   "Manage Compose deployments on Unikraft Cloud",
		Use:     "compose",
		Aliases: []string{"comp"},
		Long: heredoc.Doc(`
			Manage Compose deployments on Unikraft Cloud
		`),
		Example: heredoc.Doc(`
			# Deploy the Compose project on Unikraft Cloud
			$ unikctl cloud compose up

			# Stop the deployment
			$ unikctl cloud compose down

			# List the Compose services for this project Unikraft Cloud
			$ unikctl cloud compose ps

			# Build a specific service image of a Compose project
			$ unikctl cloud compose build nginx

			# Create a service image of a Compose project
			$ unikctl cloud compose create

			# Push a service image of Compose project
			$ unikctl cloud compose push nginx

			# View logs of a service deployment
			$ unikctl cloud compose log nginx
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "kraftcloud-compose",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(up.NewCmd())
	cmd.AddCommand(down.NewCmd())
	cmd.AddCommand(start.NewCmd())
	cmd.AddCommand(stop.NewCmd())
	cmd.AddCommand(list.NewCmd())
	cmd.AddCommand(ps.NewCmd())
	cmd.AddCommand(build.NewCmd())
	cmd.AddCommand(create.NewCmd())
	cmd.AddCommand(push.NewCmd())
	cmd.AddCommand(logs.NewCmd())

	return cmd
}

func (opts *ComposeOptions) Run(_ context.Context, _ []string) error {
	return pflag.ErrHelp
}
