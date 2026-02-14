// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package scale

import (
	"context"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/internal/cli/unikctl/cloud/scale/add"
	"unikctl.sh/internal/cli/unikctl/cloud/scale/get"
	"unikctl.sh/internal/cli/unikctl/cloud/scale/initialize"
	"unikctl.sh/internal/cli/unikctl/cloud/scale/remove"
	"unikctl.sh/internal/cli/unikctl/cloud/scale/reset"

	"unikctl.sh/cmdfactory"
)

type ScaleOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ScaleOptions{}, cobra.Command{
		Short:   "Manage instance autoscale policies",
		Use:     "scale SUBCOMMAND",
		Aliases: []string{"autoscale", "scl"},
		Example: heredoc.Doc(`
			# Add an autoscale configuration to a service
			$ unikctl cloud scale add my-service my-policy
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "kraftcloud-scale",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(remove.NewCmd())
	cmd.AddCommand(add.NewCmd())
	cmd.AddCommand(reset.NewCmd())
	cmd.AddCommand(initialize.NewCmd())
	cmd.AddCommand(get.NewCmd())

	return cmd
}

func (opts *ScaleOptions) Run(_ context.Context, _ []string) error {
	return pflag.ErrHelp
}
