// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package unikctl

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/getsentry/sentry-go"
	"github.com/rancher/wrangler/pkg/signals"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/bootstrap"
	"unikctl.sh/internal/cli"
	kitupdate "unikctl.sh/internal/update"
	kitversion "unikctl.sh/internal/version"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"

	"unikctl.sh/internal/cli/unikctl/bench"
	"unikctl.sh/internal/cli/unikctl/build"
	"unikctl.sh/internal/cli/unikctl/controlplane"
	"unikctl.sh/internal/cli/unikctl/doctor"
	"unikctl.sh/internal/cli/unikctl/inspect"
	"unikctl.sh/internal/cli/unikctl/logs"
	"unikctl.sh/internal/cli/unikctl/migrate"
	"unikctl.sh/internal/cli/unikctl/node"
	"unikctl.sh/internal/cli/unikctl/nodeagent"
	"unikctl.sh/internal/cli/unikctl/ps"
	"unikctl.sh/internal/cli/unikctl/remove"
	"unikctl.sh/internal/cli/unikctl/run"
	"unikctl.sh/internal/cli/unikctl/substrate"

	// Additional initializers
	_ "unikctl.sh/manifest"
	_ "unikctl.sh/oci"
)

type UnikctlOptions struct{}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&UnikctlOptions{}, cobra.Command{
		Short: "No-OS hosting CLI",
		Use:   "unikctl [FLAGS] SUBCOMMAND",
		Long: heredoc.Docf(`
        .
       /^\     Build and deploy no-OS applications.
      :[ ]:
      | = |    Version:          %s
     /|/=\|\   Documentation:    https://github.com/vizvasanlya/unikctl#readme
    (_:| |:_)  Issues & support: https://github.com/vizvasanlya/unikctl/issues
       v v     Platform:         https://github.com/vizvasanlya/unikctl
       ' '`, kitversion.Version()),
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
	})
	if err != nil {
		panic(err)
	}

	buildCmd := build.NewCmd()
	buildCmd.Use = "build [DIR]"
	buildCmd.Aliases = nil
	buildCmd.Short = "Build an image (release default, use --debug for debug image)"
	buildCmd.Long = "Build an application image. Default mode is release. Use --debug for symbols/tracing."
	buildCmd.Example = "unikctl build\nunikctl build --debug"
	hideAllFlagsExcept(buildCmd, "debug")

	deployCmd := run.NewCmd()
	deployCmd.Use = "deploy [PROJECT|PACKAGE|BINARY] -- [APP ARGS]"
	deployCmd.Aliases = nil
	deployCmd.Short = "Deploy an app asynchronously"
	deployCmd.Long = "Deploy an app asynchronously. Use `unikctl status` to track progress."
	deployCmd.Example = "unikctl deploy .\nunikctl deploy --debug ."
	if flag := deployCmd.Flags().Lookup("detach"); flag != nil {
		flag.DefValue = "true"
		flag.Value.Set("true")
		flag.Hidden = true
	}
	hideAllFlagsExcept(deployCmd, "debug")

	logsCmd := logs.NewCmd()
	logsCmd.Use = "logs APP"
	logsCmd.Aliases = nil
	logsCmd.Short = "Stream app logs from stdout"
	logsCmd.Long = "Stream app logs captured from the serial console stdout path."
	logsCmd.Example = "unikctl logs my-app\nunikctl logs --follow my-app"
	hideAllFlagsExcept(logsCmd, "follow")

	statusCmd := ps.NewCmd()
	statusCmd.Use = "status"
	statusCmd.Aliases = nil
	statusCmd.Short = "Show deployment status"
	statusCmd.Long = "Show deployment status."
	statusCmd.Example = "unikctl status"
	if flag := statusCmd.Flags().Lookup("all"); flag != nil {
		flag.DefValue = "true"
		flag.Value.Set("true")
		flag.Hidden = true
	}
	hideAllFlagsExcept(statusCmd)

	destroyCmd := remove.NewCmd()
	destroyCmd.Use = "destroy APP [APP...]"
	destroyCmd.Aliases = nil
	destroyCmd.Short = "Destroy one or more deployments"
	destroyCmd.Long = "Destroy one or more deployments."
	destroyCmd.Example = "unikctl destroy my-app"
	hideAllFlagsExcept(destroyCmd)

	doctorCmd := doctor.NewCmd()
	doctorCmd.Use = "doctor"
	doctorCmd.Aliases = nil
	doctorCmd.Short = "Run host diagnostics"
	doctorCmd.Long = "Run host diagnostics for qemu/kvm/network/runtime/control-plane prerequisites."
	hideAllFlagsExcept(doctorCmd)

	migrateCmd := migrate.NewCmd()
	migrateCmd.Use = "migrate"
	migrateCmd.Aliases = nil
	migrateCmd.Short = "Migrate Docker/Compose projects to unikctl"
	migrateCmd.Long = "Generate unikctl-native migration files from Dockerfile and docker-compose inputs."
	hideAllFlagsExcept(migrateCmd)

	nodeCmd := node.NewCmd()
	nodeCmd.Use = "node"
	nodeCmd.Aliases = nil
	nodeCmd.Short = "Manage scheduler nodes"
	nodeCmd.Long = "Manage scheduler nodes (list/cordon/uncordon/drain)."
	hideAllFlagsExcept(nodeCmd)

	inspectCmd := inspect.NewCmd()
	inspectCmd.Use = "inspect APP"
	inspectCmd.Aliases = nil
	inspectCmd.Short = "Inspect one deployment in detail"
	inspectCmd.Long = "Inspect one deployment and show runtime driver, resource allocation, and snapshot state."
	hideAllFlagsExcept(inspectCmd)

	benchCmd := bench.NewCmd()
	benchCmd.Use = "bench"
	benchCmd.Aliases = nil
	benchCmd.Short = "Benchmark helpers for boot and density"
	benchCmd.Long = "Benchmark helpers for density planning and boot lifecycle metrics."
	hideAllFlagsExcept(benchCmd)

	substrateCmd := substrate.NewCmd()
	substrateCmd.Use = "substrate"
	substrateCmd.Aliases = nil
	substrateCmd.Short = "Inspect substrate-level runtime state"
	substrateCmd.Long = "Inspect driver defaults, snapshot fast-path, warm pool, density, and per-tenant utilization."
	hideAllFlagsExcept(substrateCmd)

	controlPlaneCmd := controlplane.NewCmd()
	controlPlaneCmd.Hidden = true

	nodeAgentCmd := nodeagent.NewCmd()
	nodeAgentCmd.Hidden = true

	cmd.AddCommand(buildCmd)
	cmd.AddCommand(deployCmd)
	cmd.AddCommand(logsCmd)
	cmd.AddCommand(statusCmd)
	cmd.AddCommand(destroyCmd)
	cmd.AddCommand(doctorCmd)
	cmd.AddCommand(migrateCmd)
	cmd.AddCommand(nodeCmd)
	cmd.AddCommand(inspectCmd)
	cmd.AddCommand(benchCmd)
	cmd.AddCommand(substrateCmd)
	cmd.AddCommand(controlPlaneCmd)
	cmd.AddCommand(nodeAgentCmd)

	return cmd
}

func hideAllFlagsExcept(cmd *cobra.Command, allowed ...string) {
	allowedSet := map[string]struct{}{}

	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := allowedSet[flag.Name]; !ok {
			flag.Hidden = true
		}
	})

	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := allowedSet[flag.Name]; !ok {
			flag.Hidden = true
		}
	})

	cmd.InheritedFlags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := allowedSet[flag.Name]; !ok {
			flag.Hidden = true
		}
	})
}

func hideRootFlagsExcept(cmd *cobra.Command, allowed ...string) {
	allowedSet := map[string]struct{}{}

	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := allowedSet[flag.Name]; !ok {
			flag.Hidden = true
		}
	})

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if _, ok := allowedSet[flag.Name]; !ok {
			flag.Hidden = true
		}
	})
}

func (k *UnikctlOptions) Run(_ context.Context, args []string) error {
	return pflag.ErrHelp
}

// The Sentry DSN to use for anonymous telemetry.
var sentryDsn = ""

func Main(args []string) int {
	cmd := NewCmd()
	ctx := signals.SetupSignalContext()
	copts := &cli.CliOptions{}

	// Start CPU profile when environmental variable is set.
	if cpuProfile := os.Getenv("UNIKCTL_CPU_PROFILE"); len(cpuProfile) > 0 {
		pprofFile, err := os.OpenFile(cpuProfile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Println("could not create cpu profile file")
			os.Exit(1)
		}

		// Start profiling
		if err = pprof.StartCPUProfile(pprofFile); err != nil {
			fmt.Println("could not start cpu profiling")
			os.Exit(1)
		}

		// Stop profiling on exit
		defer func() {
			pprof.StopCPUProfile()
			_ = pprofFile.Close()
		}()
	}

	for _, o := range []cli.CliOption{
		cli.WithDefaultConfigManager(cmd),
		cli.WithDefaultIOStreams(),
		cli.WithDefaultLogger(),
		cli.WithDefaultHTTPClient(),
	} {
		if err := o(copts); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	hideRootFlagsExcept(cmd, "help")

	// Set up the config manager in the context if it is available
	ctx = config.WithConfigManager(ctx, copts.ConfigManager)

	// Hydrate KraftCloud configuration
	if newCtx, err := config.HydrateKraftCloudAuthInContext(ctx); err == nil {
		ctx = newCtx
	}

	// Set up the logger in the context if it is available
	ctx = log.WithLogger(ctx, copts.Logger)

	// Add the unikctl version to the debug logs
	log.G(ctx).
		WithField("version", kitversion.Version()).
		Debugf("unikctl")

	collectTelemetry := sentryDsn != "" && config.G[config.KraftKit](ctx).CollectAnonymousTelemetry

	if collectTelemetry {
		sentryDsn, err := base64.StdEncoding.DecodeString(sentryDsn)
		if err != nil {
			collectTelemetry = false
		} else {
			if err := sentry.Init(sentry.ClientOptions{
				Dsn:              string(sentryDsn),
				Release:          kitversion.Version(),
				TracesSampleRate: 1.0,
			}); err != nil {
				log.G(ctx).Debugf("could not initialize sentry: %v", err)
			} else {
				log.G(ctx).Debug("collecting anonymous telemetry - to disable export UNIKCTL_COLLECT_ANONYMOUS_TELEMETRY=false")
			}
		}
	}

	defer func() {
		if err := recover(); err != nil {
			if collectTelemetry {
				sentry.CurrentHub().RecoverWithContext(ctx, err)
				sentry.Flush(time.Second * 5)
			}

			// Use copts.Logger as access to log.G(ctx) may not be available in the
			// panic state.
			copts.Logger.Logf(logrus.FatalLevel, "a fatal error occurred: %s", err)

			recoverLevel := logrus.DebugLevel
			if !collectTelemetry {
				recoverLevel = logrus.ErrorLevel
			}

			// Only log the stack trace if the user has opted-out of telemetry such
			// that they can see the stack trace and report the issue.  Otherwise,
			// silently log these to the debug level and suggest the user to open an
			// issue.
			for _, line := range strings.Split(string(debug.Stack()), "\n") {
				copts.Logger.Log(recoverLevel, line)
			}
			if !collectTelemetry {
				copts.Logger.Log(logrus.FatalLevel, "please consider opening an issue at: https://github.com/unikctl/unikctl/issues/new")
			}
		}
	}()

	// Set up the iostreams in the context if it is available
	if copts.IOStreams != nil {
		ctx = iostreams.WithIOStreams(ctx, copts.IOStreams)
	}

	if (os.Getenv("SUDO_UID") != "" || os.Getenv("SUDO_GID") != "" || os.Getenv("SUDO_USER") != "") && !config.G[config.KraftKit](ctx).NoWarnSudo {
		log.G(ctx).Warn("detected invocation via sudo!")
		log.G(ctx).Warn("")
		log.G(ctx).Warn("mixing invocations of unikctl with sudo can lead to unexpected behavior")
		log.G(ctx).Warn("read more on how to use unikctl without sudo at:")
		log.G(ctx).Warn("")
		log.G(ctx).Warn("\thttps://github.com/vizvasanlya/unikctl#readme")
		log.G(ctx).Warn("")
		log.G(ctx).Warn("to hide and ignore this warning message, set the environmental variable:")
		log.G(ctx).Warn("")
		log.G(ctx).Warn("\texport UNIKCTL_NO_WARN_SUDO=1")
		log.G(ctx).Warn("")
	}

	if !config.G[config.KraftKit](ctx).NoCheckUpdates {
		if err := kitupdate.Check(ctx); err != nil {
			log.G(ctx).Debugf("could not check for updates: %v", err)
			log.G(ctx).Debug("")
			log.G(ctx).Debug("to turn off this check, set:")
			log.G(ctx).Debug("")
			log.G(ctx).Debug("\texport UNIKCTL_NO_CHECK_UPDATES=true")
			log.G(ctx).Debug("")
			log.G(ctx).Debug("or use the globally accessible flag '--no-check-updates'")
		}
	}

	if err := bootstrap.InitKraftkit(ctx); err != nil {
		log.G(ctx).Errorf("could not init unikctl: %v", err)
		os.Exit(1)
	}

	hideRootFlagsExcept(cmd, "help")

	return cmdfactory.Main(ctx, cmd)
}
