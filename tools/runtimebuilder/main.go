// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"unikctl.sh/config"
	"unikctl.sh/internal/bootstrap"
	"unikctl.sh/internal/cli"
	pkgcmd "unikctl.sh/internal/cli/unikctl/pkg"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"
	"unikctl.sh/packmanager"

	// Register package managers.
	_ "unikctl.sh/manifest"
	_ "unikctl.sh/oci"
)

func main() {
	var (
		source = flag.String("source", "", "Runtime project source directory")
		name   = flag.String("name", "", "Runtime package name (e.g. ghcr.io/org/repo/base:latest)")
		arch   = flag.String("arch", "x86_64", "Target architecture")
		plat   = flag.String("plat", "qemu", "Target platform")
		push   = flag.Bool("push", true, "Push package after build")
	)
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		fatalf("missing --source")
	}
	if strings.TrimSpace(*name) == "" {
		fatalf("missing --name")
	}

	ctx, copts, err := initContext()
	if err != nil {
		fatalf("initializing runtime builder context: %v", err)
	}

	// Keep runtime build deterministic in automation.
	config.G[config.KraftKit](ctx).NoPrompt = true
	config.G[config.KraftKit](ctx).NoCheckUpdates = true
	config.G[config.KraftKit](ctx).CollectAnonymousTelemetry = false

	if err := bootstrap.InitKraftkit(ctx); err != nil {
		fatalf("initializing unikctl runtime: %v", err)
	}

	ctx, err = packmanager.WithDefaultUmbrellaManagerInContext(ctx)
	if err != nil {
		fatalf("initializing package managers: %v", err)
	}

	opts := &pkgcmd.PkgOptions{
		Architecture: strings.TrimSpace(*arch),
		Format:       "oci",
		Name:         strings.TrimSpace(*name),
		NoPull:       false,
		Platform:     strings.TrimSpace(*plat),
		Push:         *push,
		Strategy:     packmanager.StrategyMerge,
		Workdir:      strings.TrimSpace(*source),
	}

	if _, err := pkgcmd.Pkg(ctx, opts, opts.Workdir); err != nil {
		fatalf("building runtime package %s: %v", opts.Name, err)
	}

	fmt.Fprintf(copts.IOStreams.Out, "built runtime package: %s\n", opts.Name)
}

func initContext() (context.Context, *cli.CliOptions, error) {
	ctx := context.Background()
	cmd := &cobra.Command{Use: "runtimebuilder"}
	copts := &cli.CliOptions{}

	for _, opt := range []cli.CliOption{
		cli.WithDefaultConfigManager(cmd),
		cli.WithDefaultIOStreams(),
		cli.WithDefaultLogger(),
		cli.WithDefaultHTTPClient(),
	} {
		if err := opt(copts); err != nil {
			return nil, nil, err
		}
	}

	ctx = config.WithConfigManager(ctx, copts.ConfigManager)
	ctx = log.WithLogger(ctx, copts.Logger)
	ctx = iostreams.WithIOStreams(ctx, copts.IOStreams)

	return ctx, copts, nil
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
