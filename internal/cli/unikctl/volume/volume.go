// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package volume

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/cli/unikctl/volume/create"
	"unikctl.sh/internal/cli/unikctl/volume/inspect"
	"unikctl.sh/internal/cli/unikctl/volume/list"
	"unikctl.sh/internal/cli/unikctl/volume/remove"
	"unikctl.sh/internal/set"
	"unikctl.sh/machine/volume"
)

type Volume struct {
	Driver string `local:"false" long:"driver" short:"d" usage:"Set the volume driver."`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&Volume{}, cobra.Command{
		Short:   "Manage machine volumes",
		Use:     "vol SUBCOMMAND",
		Aliases: []string{"volume", "vols", "volumes"},
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup:  "vol",
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.AddCommand(create.NewCmd())
	cmd.AddCommand(inspect.NewCmd())
	cmd.AddCommand(list.NewCmd())
	cmd.AddCommand(remove.NewCmd())

	return cmd
}

func (opts *Volume) Pre(cmd *cobra.Command, _ []string) error {
	if opts.Driver == "" {
		opts.Driver = strings.TrimSpace(volume.DefaultStrategyName())
	}
	if opts.Driver == "" {
		return fmt.Errorf("volume driver must be set (no compatible volume drivers available)")
	} else if !set.NewStringSet(volume.DriverNames()...).Contains(opts.Driver) {
		return fmt.Errorf("unsupported volume driver strategy: %s", opts.Driver)
	}

	return nil
}

func (opts *Volume) Run(ctx context.Context, args []string) error {
	return pflag.ErrHelp
}
