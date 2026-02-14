// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package controlplane

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneserver"
	"unikctl.sh/log"
)

type ControlPlaneOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ControlPlaneOptions{}, cobra.Command{
		Use:    "control-plane",
		Short:  "Run control plane service",
		Hidden: true,
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpHidden: "true",
		},
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *ControlPlaneOptions) Run(ctx context.Context, _ []string) error {
	listen := config.G[config.KraftKit](ctx).ControlPlane.Listen
	workers := config.G[config.KraftKit](ctx).ControlPlane.MaxConcurrentOps

	if envListen := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_LISTEN")); envListen != "" {
		listen = envListen
	}
	if envWorkers := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_MAX_CONCURRENT_OPS")); envWorkers != "" {
		if parsed, err := strconv.Atoi(envWorkers); err == nil && parsed > 0 {
			workers = parsed
		}
	}

	server, err := controlplaneserver.New(ctx, listen, workers)
	if err != nil {
		return err
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"listen":  listen,
		"workers": workers,
	}).Info("starting control plane")

	if err := server.Run(); err != nil {
		return fmt.Errorf("control plane server stopped: %w", err)
	}

	return nil
}
