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

	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/cli/unikctl/compose/build"
	"unikctl.sh/internal/cli/unikctl/compose/create"
	"unikctl.sh/internal/cli/unikctl/compose/down"
	"unikctl.sh/internal/cli/unikctl/compose/logs"
	"unikctl.sh/internal/cli/unikctl/compose/ls"
	"unikctl.sh/internal/cli/unikctl/compose/pause"
	"unikctl.sh/internal/cli/unikctl/compose/ps"
	"unikctl.sh/internal/cli/unikctl/compose/pull"
	"unikctl.sh/internal/cli/unikctl/compose/push"
	"unikctl.sh/internal/cli/unikctl/compose/start"
	"unikctl.sh/internal/cli/unikctl/compose/stop"
	"unikctl.sh/internal/cli/unikctl/compose/unpause"
	"unikctl.sh/internal/cli/unikctl/compose/up"
)

type ComposeOptions struct {
	Composefile string `long:"file" short:"f" usage:"Set the Compose file."`
	EnvFile     string `long:"env-file" usage:"Set the environment file."`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ComposeOptions{}, cobra.Command{
		Short:   "Build and run compose projects with Unikraft",
		Use:     "compose [FLAGS] [SUBCOMMAND|DIR]",
		Aliases: []string{},
		Long: heredoc.Docf(`
			Build and run compose projects with Unikraft.
		`),
		Example: heredoc.Doc(`
			# Start a compose project
			$ unikctl compose up
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "compose",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(build.NewCmd())
	cmd.AddCommand(create.NewCmd())
	cmd.AddCommand(down.NewCmd())
	cmd.AddCommand(logs.NewCmd())
	cmd.AddCommand(ls.NewCmd())
	cmd.AddCommand(pause.NewCmd())
	cmd.AddCommand(ps.NewCmd())
	cmd.AddCommand(pull.NewCmd())
	cmd.AddCommand(push.NewCmd())
	cmd.AddCommand(start.NewCmd())
	cmd.AddCommand(stop.NewCmd())
	cmd.AddCommand(unpause.NewCmd())
	cmd.AddCommand(up.NewCmd())

	return cmd
}

func (opts *ComposeOptions) Pre(cmd *cobra.Command, _ []string) error {
	return nil
}

func (opts *ComposeOptions) Run(_ context.Context, _ []string) error {
	return pflag.ErrHelp
}
