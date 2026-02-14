// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package migrate

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/cmdfactory"
)

type MigrateOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&MigrateOptions{}, cobra.Command{
		Use:   "migrate",
		Short: "Migrate Docker/Compose inputs to unikctl-native config",
		Args:  cobra.NoArgs,
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(newDockerfileCmd())
	cmd.AddCommand(newComposeCmd())

	return cmd
}

func (opts *MigrateOptions) Run(context.Context, []string) error {
	return pflag.ErrHelp
}
