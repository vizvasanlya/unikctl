// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package remove

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	networkapi "unikctl.sh/api/network/v1alpha1"
	volumeapi "unikctl.sh/api/volume/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"
	"unikctl.sh/machine/network"
	mplatform "unikctl.sh/machine/platform"
	"unikctl.sh/machine/volume"
)

type RemoveOptions struct {
	All      bool   `long:"all" usage:"Remove all machines"`
	Platform string `noattribute:"true"`
}

// Remove stops and deletes a local Unikraft virtual machine.
func Remove(ctx context.Context, opts *RemoveOptions, args ...string) error {
	if opts == nil {
		opts = &RemoveOptions{}
	}

	return opts.Run(ctx, args)
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&RemoveOptions{}, cobra.Command{
		Short:   "Remove one or more running unikernels",
		Use:     "remove [FLAGS] MACHINE [MACHINE [...]]",
		Args:    cobra.MinimumNArgs(0),
		Aliases: []string{"rm"},
		Long: heredoc.Doc(`
			Remove one or more running unikernels
		`),
		Example: heredoc.Doc(`
			# Remove a running unikernel
			$ unikctl rm my-machine
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

func (opts *RemoveOptions) Pre(cmd *cobra.Command, _ []string) error {
	opts.Platform = cmd.Flag("plat").Value.String()
	return nil
}

func (opts *RemoveOptions) Run(ctx context.Context, args []string) (retErr error) {
	var err error

	if len(args) == 0 && !opts.All {
		return fmt.Errorf("no machine(s) specified")
	}

	if len(args) > 0 && opts.All {
		return fmt.Errorf("cannot specify machines and --all at the same time")
	}

	if controlplaneapi.Enabled(ctx) {
		return opts.remoteDestroy(ctx, args)
	}

	platform := mplatform.PlatformUnknown
	var controller machineapi.MachineService

	if opts.All || opts.Platform == "all" {
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

	var remove []machineapi.Machine

	if len(args) == 0 && opts.All {
		remove = machines.Items
	} else {
		for _, arg := range args {
			for _, machine := range machines.Items {
				if arg == machine.Name || arg == string(machine.UID) {
					remove = append(remove, machine)
				}
			}
		}
	}

	if len(remove) == 0 {
		return fmt.Errorf("machine(s) not found")
	}

	targets := make([]string, 0, len(remove))
	for _, machine := range remove {
		targets = append(targets, machine.Name)
	}

	var opStore *operations.Store
	var opRecord *operations.Record
	if !controlplaneapi.InServerMode(ctx) {
		var opErr error
		opStore, opRecord, opErr = startDestroyOperation(ctx, targets)
		if opErr != nil {
			log.G(ctx).WithError(opErr).Debug("could not initialize operation tracking")
		}
		if opStore != nil && opRecord != nil {
			fmt.Fprintf(iostreams.G(ctx).ErrOut, "operation: %s\n", opRecord.ID)
			if err := opStore.SetState(opRecord.ID, operations.StateRunning, "destroy in progress"); err != nil {
				log.G(ctx).WithError(err).Debug("could not update destroy operation state")
			}
		}
	}

	completionMessage := "destroy completed"
	defer func() {
		if opStore == nil || opRecord == nil {
			return
		}

		if retErr != nil {
			if err := opStore.Fail(opRecord.ID, retErr); err != nil {
				log.G(ctx).WithError(err).Debug("could not mark destroy operation as failed")
			}
			return
		}

		if err := opStore.SetState(opRecord.ID, operations.StateSucceeded, completionMessage); err != nil {
			log.G(ctx).WithError(err).Debug("could not mark destroy operation as succeeded")
		}
	}()

	netcontrollers := make(map[string]networkapi.NetworkService, 0)
	var errs []error
	removedCount := 0

	for _, machine := range remove {
		// First remove all the associated network interfaces.
		for _, net := range machine.Spec.Networks {
			netcontroller, ok := netcontrollers[net.Driver]

			// Store the instantiation of the network controller strategy.
			if !ok {
				strategy, ok := network.Strategies()[net.Driver]
				if !ok {
					return fmt.Errorf("unknown machine network driver: %s", net.Driver)
				}

				netcontroller, err = strategy.NewNetworkV1alpha1(ctx)
				if err != nil {
					return err
				}

				netcontrollers[net.Driver] = netcontroller
			}

			networks, err := netcontroller.List(ctx, &networkapi.NetworkList{})
			if err != nil {
				return err
			}
			var found *networkapi.Network

			for _, network := range networks.Items {
				if network.Spec.IfName == net.IfName {
					found = &network
					break
				}
			}
			if found == nil {
				log.G(ctx).Warnf("could not get network information for %s", net.IfName)
				continue
			}

			for _, machineIface := range net.Interfaces {
				// Remove the associated network interfaces
				for i, netIface := range found.Spec.Interfaces {
					if machineIface.UID == netIface.UID {
						ret := make([]networkapi.NetworkInterfaceTemplateSpec, 0)
						ret = append(ret, found.Spec.Interfaces[:i]...)
						found.Spec.Interfaces = append(ret, found.Spec.Interfaces[i+1:]...)
						break
					}
				}

				if _, err = netcontroller.Update(ctx, found); err != nil {
					log.G(ctx).Warnf("could not update network %s: %v", net.IfName, err)
					continue
				}
			}
		}

		// Update volume information.
		if len(machine.Spec.Volumes) > 0 {
			volumeController, err := volume.NewVolumeV1alpha1ServiceIterator(ctx)
			if err != nil {
				return fmt.Errorf("could not get volume controller: %v", err)
			}
			for _, vol := range machine.Spec.Volumes {
				stillUsed := false
				allMachines, err := controller.List(ctx, &machineapi.MachineList{})
				if err != nil {
					return err
				}
				for _, m := range allMachines.Items {
					if m.ObjectMeta.UID == machine.ObjectMeta.UID {
						continue
					}
					for _, v := range m.Spec.Volumes {
						if v.ObjectMeta.UID == vol.ObjectMeta.UID {
							stillUsed = true
							break
						}
					}

					if stillUsed {
						break
					}
				}

				if !stillUsed {
					vol.Status.State = volumeapi.VolumeStatePending
					if _, err := volumeController.Update(ctx, &vol); err != nil {
						log.G(ctx).Warnf("could not update volume %s: %v", vol.Name, err)
					}
				}
			}
		}

		// Stop the machine before deleting it.
		if _, err := controller.Stop(ctx, &machine); err != nil {
			log.G(ctx).Errorf("could not stop machine %s: %v", machine.Name, err)
			errs = append(errs, fmt.Errorf("could not stop machine %s: %w", machine.Name, err))
		}

		// Now delete the machine.
		if _, err := controller.Delete(ctx, &machine); err != nil {
			log.G(ctx).Errorf("could not delete machine %s: %v", machine.Name, err)
			errs = append(errs, fmt.Errorf("could not delete machine %s: %w", machine.Name, err))
		} else {
			removedCount++
			fmt.Fprintln(iostreams.G(ctx).Out, machine.Name)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	completionMessage = fmt.Sprintf("destroyed %d machine(s)", removedCount)

	return nil
}

func startDestroyOperation(ctx context.Context, targets []string) (*operations.Store, *operations.Record, error) {
	store, err := operations.NewStore(ctx)
	if err != nil {
		return nil, nil, err
	}

	record, err := store.Start(operations.KindDestroy, targets, "destroy queued")
	if err != nil {
		return nil, nil, err
	}

	return store, record, nil
}

func (opts *RemoveOptions) remoteDestroy(ctx context.Context, args []string) error {
	client, err := controlplaneapi.NewClientFromContext(ctx)
	if err != nil {
		return err
	}

	traceID := removeTraceID()
	response, err := client.Destroy(ctx, controlplaneapi.DestroyRequest{
		Names:          args,
		All:            opts.All,
		IdempotencyKey: destroyIdempotencyKey(args, opts.All),
		TraceID:        traceID,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(iostreams.G(ctx).ErrOut, "operation: %s\n", response.OperationID)
	if response.Reused {
		fmt.Fprintf(iostreams.G(ctx).ErrOut, "reused existing operation via idempotency key\n")
	}
	return nil
}

func removeTraceID() string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "trace-remove"
	}
	return fmt.Sprintf("trace-%x", random)
}

func destroyIdempotencyKey(names []string, all bool) string {
	payload := strings.Join(names, "\x00") + fmt.Sprintf("\x1f%t", all)
	sum := sha256.Sum256([]byte(payload))
	return "destroy-" + hex.EncodeToString(sum[:12])
}
