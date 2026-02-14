// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package logs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/waitgroup"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"
	mplatform "unikctl.sh/machine/platform"
)

type LogOptions struct {
	Follow   bool   `long:"follow" short:"f" usage:"Follow log output"`
	Platform string `noattribute:"true"`
	NoPrefix bool   `long:"no-prefix" usage:"When logging multiple machines, do not prefix each log line with the name"`
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&LogOptions{}, cobra.Command{
		Short:   "Fetch app logs",
		Use:     "logs [FLAGS] MACHINE",
		Args:    cobra.MinimumNArgs(1),
		Aliases: []string{"log"},
		Long: heredoc.Doc(`
			Fetch logs from the serial-console stdout stream.
		`),
		Example: heredoc.Doc(`
			# Fetch the logs of an app
			$ unikctl logs my-machine

			# Fetch logs across all replicas of a service (control-plane mode)
			$ unikctl logs storefront

			# Fetch the logs and follow the output
			$ unikctl logs --follow my-machine

			# Follow logs across all replicas of a service
			$ unikctl logs --follow storefront

			# Fetch the logs of multiple apps and follow the output
			$ unikctl logs --follow my-machine1 my-machine2
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.Flags().VarP(
		cmdfactory.NewEnumFlag(
			mplatform.Platforms(),
			mplatform.Platform("all"),
		),
		"plat",
		"p",
		"Set the platform virtual machine monitor driver. Set to 'all' to match all platforms (default).",
	)

	return cmd
}

func (opts *LogOptions) Pre(cmd *cobra.Command, _ []string) error {
	opts.Platform = cmd.Flag("plat").Value.String()

	return nil
}

func (opts *LogOptions) Run(ctx context.Context, args []string) error {
	var err error

	if controlplaneapi.Enabled(ctx) {
		client, err := controlplaneapi.NewClientFromContext(ctx)
		if err != nil {
			return err
		}

		if len(args) != 1 {
			return fmt.Errorf("remote logs support one app at a time")
		}

		return client.Logs(ctx, args[0], opts.Follow, iostreams.G(ctx).Out)
	}

	platform := mplatform.PlatformUnknown
	var controller machineapi.MachineService

	if opts.Platform == "all" {
		controller, err = mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	} else {
		var ok bool
		platform, ok = mplatform.PlatformsByName()[opts.Platform]
		if !ok {
			return fmt.Errorf("unknown platform driver: %s", opts.Platform)
		}

		strategy, ok := mplatform.Strategies()[platform]
		if !ok {
			return fmt.Errorf("unsupported platform driver: %s (contributions welcome!)", platform.String())
		}

		controller, err = strategy.NewMachineV1alpha1(ctx)
	}
	if err != nil {
		return err
	}

	machines, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return err
	}

	loggedMachines := []*machineapi.Machine{}

	// Although this looks duplicated, it allows us to check whether all arguments
	// are a valid machine while also not having duplicated logging in case of
	// multiple equal arguments (or both the name and UID).
	for _, candidate := range machines.Items {
		for _, arg := range args {
			if arg == candidate.Name || arg == string(candidate.UID) {
				loggedMachines = append(loggedMachines, &candidate)
				break
			}
		}
	}

	for _, arg := range args {
		found := false
		for _, machine := range loggedMachines {
			if arg == machine.Name || arg == string(machine.UID) {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("could not find instance %s", arg)
		}
	}

	longestName := 0

	if len(loggedMachines) > 1 && !opts.NoPrefix {
		for _, machine := range loggedMachines {
			if len(machine.Name) > longestName {
				longestName = len(machine.Name)
			}
		}
	} else {
		opts.NoPrefix = true
	}

	var errGroup []error
	observations := waitgroup.WaitGroup[*machineapi.Machine]{}

	for _, machine := range loggedMachines {
		prefix := ""
		if !opts.NoPrefix {
			prefix = machine.Name + strings.Repeat(" ", longestName-len(machine.Name))
		}
		consumer, err := NewColorfulConsumer(iostreams.G(ctx), !config.G[config.KraftKit](ctx).NoColor, prefix)
		if err != nil {
			errGroup = append(errGroup, err)
		}

		// Sometimes the kernel can boot and exit faster than we can start tailing the logs.
		// In both snapshot and follow modes, consume logs via the machine service
		// stream abstraction to keep CLI behavior aligned with serial->host->CLI.
		if opts.Follow && (machine.Status.State == machineapi.MachineStateRunning || machine.Status.State == machineapi.MachineStateExited) {
			observations.Add(machine)
			go func(machine *machineapi.Machine) {
				defer func() {
					observations.Done(machine)
				}()

				if err = FollowLogs(ctx, machine, controller, consumer); err != nil {
					errGroup = append(errGroup, err)
					return
				}
			}(machine)
		} else if err := SnapshotLogs(ctx, machine, controller, consumer); err != nil {
			errGroup = append(errGroup, err)
		}
	}

	observations.Wait()

	return errors.Join(errGroup...)
}

// SnapshotLogs reads the currently available stream and returns when EOF is observed.
func SnapshotLogs(ctx context.Context, machine *machineapi.Machine, controller machineapi.MachineService, consumer LogConsumer) error {
	logs, errs, err := controller.Logs(ctx, machine)
	if err != nil {
		return fmt.Errorf("accessing logs: %w", err)
	}

	for {
		select {
		case line := <-logs:
			consumer.Consume(line)

		case err := <-errs:
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}

			return fmt.Errorf("reading logs: %w", err)

		case <-ctx.Done():
			return nil
		}
	}
}

// FollowLogs tracks the logs generated by a machine and prints them to the context out stream.
func FollowLogs(ctx context.Context, machine *machineapi.Machine, controller machineapi.MachineService, consumer LogConsumer) error {
	ctx, cancel := context.WithCancel(ctx)

	var exitErr error
	var eof bool

	go func() {
		events, errs, err := controller.Watch(ctx, machine)
		if err != nil {
			if eof {
				cancel()
				return
			}

			// There is a chance that the kernel has booted and exited faster than an
			// event stream can be initialized and interpreted by unikctl.  This
			// typically happens on M-series processors from Apple.  In the event of
			// an error, first statically check the state of the machine.  If the
			// machine has exited, we can simply return early such that the logs can
			// be output appropriately.
			machine, getMachineErr := controller.Get(ctx, machine)
			if err != nil {
				cancel()
				err = fmt.Errorf("getting the machine information: %w: %w", getMachineErr, err)
			}
			if machine.Status.State == machineapi.MachineStateExited {
				// Calling cancel() in every execution path of this Go routine following
				// the static detection of a preemptive exit state (since the event
				// stream is no longer available) would prevent the tailing of the now
				// finite logs.  A return here without calling cancel() guarantees a
				// graceful exit and the output of said logs.
				return
			}

			cancel()
			exitErr = fmt.Errorf("listening to machine events: %w", err)
			return
		}

	loop:
		for {
			// Wait on either channel
			select {
			case status := <-events:
				switch status.Status.State {
				case machineapi.MachineStateErrored:
					exitErr = fmt.Errorf("machine fatally exited")
					cancel()
					break loop

				case machineapi.MachineStateExited, machineapi.MachineStateFailed:
					cancel()
					break loop
				}

			case err := <-errs:
				log.G(ctx).Errorf("received event error: %v", err)
				exitErr = err
				cancel()
				break loop

			case <-ctx.Done():
				break loop
			}
		}
	}()

	logs, errs, err := controller.Logs(ctx, machine)
	if err != nil {
		cancel()
		return fmt.Errorf("accessing logs: %w", err)
	}

loop:
	for {
		// Wait on either channel
		select {
		case line := <-logs:
			consumer.Consume(line)

		case err := <-errs:
			eof = true
			if !errors.Is(err, io.EOF) {
				log.G(ctx).Errorf("received event error: %v", err)
				return fmt.Errorf("event: %w", err)
			}

		case <-ctx.Done():
			break loop
		}
	}

	return exitErr
}
