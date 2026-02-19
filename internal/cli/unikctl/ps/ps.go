// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file expect in compliance with the License.
package ps

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/internal/cli/unikctl/cloud/utils"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
	"unikctl.sh/internal/tableprinter"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"
	mplatform "unikctl.sh/machine/platform"

	"github.com/MakeNowJust/heredoc"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
)

type PsOptions struct {
	Architecture string `long:"arch" short:"m" usage:"Filter the list by architecture"`
	Long         bool   `long:"long" short:"l" usage:"Show more information"`
	platform     string
	Quiet        bool   `long:"quiet" short:"q" usage:"Only display machine IDs"`
	ShowAll      bool   `long:"all" short:"a" usage:"Show all machines (default shows just running)"`
	Output       string `long:"output" short:"o" usage:"Set output format. Options: table,yaml,json,list" default:"table"`
	remoteOps    []OperationEntry
	remoteSvcs   []ServiceEntry
}

const (
	MemoryMiB = 1024 * 1024
	operationStaleAfter = 15 * time.Minute
)

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&PsOptions{}, cobra.Command{
		Short:   "List running unikernels",
		Use:     "ps [FLAGS]",
		Args:    cobra.MaximumNArgs(0),
		Aliases: []string{},
		Long:    "List running unikernels",
		Example: heredoc.Doc(`
			# List all running unikernels
			$ unikctl ps

			# List all unikernels
			$ unikctl ps --all

			# List all unikernels with more information
			$ unikctl ps --long
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.Flags().VarP(
		cmdfactory.NewEnumFlag[mplatform.Platform](
			mplatform.Platforms(),
			mplatform.Platform("all"),
		),
		"plat",
		"p",
		"Set the platform virtual machine monitor driver.",
	)

	return cmd
}

func (opts *PsOptions) Pre(cmd *cobra.Command, _ []string) error {
	opts.platform = cmd.Flag("plat").Value.String()

	if !utils.IsValidOutputFormat(opts.Output) {
		return fmt.Errorf("invalid output format: %s", opts.Output)
	}

	return nil
}

type PsEntry struct {
	ID         string
	Name       string
	Kernel     string
	Args       string
	Created    string
	State      machineapi.MachineState
	Mem        string
	Ports      string
	Service    string
	PublicPort string
	URL        string
	Pid        int32
	Arch       string
	Plat       string
	IPs        []string
}

type OperationEntry struct {
	ID      string
	Kind    operations.Kind
	Target  string
	State   operations.State
	Attempt int
	Updated string
	Message string
}

type ServiceEntry struct {
	Name        string
	Strategy    string
	Phase       string
	Ready       int
	Desired     int
	Machines    string
	Message     string
	LastError   string
	LastHealthy string
	Updated     string
}

type colorFunc func(string) string

var (
	MachineStateColor = map[machineapi.MachineState]colorFunc{
		machineapi.MachineStateUnknown:    iostreams.Gray,
		machineapi.MachineStateCreated:    iostreams.Blue,
		machineapi.MachineStateFailed:     iostreams.Red,
		machineapi.MachineStateRestarting: iostreams.Yellow,
		machineapi.MachineStateRunning:    iostreams.Green,
		machineapi.MachineStatePaused:     iostreams.Yellow,
		machineapi.MachineStateSuspended:  iostreams.Yellow,
		machineapi.MachineStateExited:     iostreams.Gray,
		machineapi.MachineStateErrored:    iostreams.Red,
	}
	MachineStateColorNil = map[machineapi.MachineState]colorFunc{
		machineapi.MachineStateUnknown:    nil,
		machineapi.MachineStateCreated:    nil,
		machineapi.MachineStateFailed:     nil,
		machineapi.MachineStateRestarting: nil,
		machineapi.MachineStateRunning:    nil,
		machineapi.MachineStatePaused:     nil,
		machineapi.MachineStateSuspended:  nil,
		machineapi.MachineStateExited:     nil,
		machineapi.MachineStateErrored:    nil,
	}
	OperationStateColor = map[operations.State]colorFunc{
		operations.StatePending:   iostreams.Blue,
		operations.StateRunning:   iostreams.Yellow,
		operations.StateSubmitted: iostreams.Blue,
		operations.StateSucceeded: iostreams.Green,
		operations.StateFailed:    iostreams.Red,
	}
	OperationStateColorNil = map[operations.State]colorFunc{
		operations.StatePending:   nil,
		operations.StateRunning:   nil,
		operations.StateSubmitted: nil,
		operations.StateSucceeded: nil,
		operations.StateFailed:    nil,
	}
)

func (opts *PsOptions) Run(ctx context.Context, _ []string) error {
	items, err := opts.PsTable(ctx)
	if err != nil {
		return err
	}

	return opts.PrintPsTable(ctx, items)
}

func (opts *PsOptions) PsTable(ctx context.Context) ([]PsEntry, error) {
	var err error
	var items []PsEntry

	if controlplaneapi.Enabled(ctx) {
		client, err := controlplaneapi.NewClientFromContext(ctx)
		if err != nil {
			return nil, err
		}

		status, err := client.Status(ctx)
		if err != nil {
			return nil, err
		}

		opts.remoteOps = make([]OperationEntry, 0, len(status.Operations))
		for _, operation := range status.Operations {
			state := operations.State(operation.State)
			if _, ok := OperationStateColor[state]; !ok {
				state = operations.StatePending
			}

			message := strings.TrimSpace(operation.Message)
			if operation.Error != "" {
				message = operation.Error
			}
			if message == "" {
				message = "-"
			}

			opts.remoteOps = append(opts.remoteOps, OperationEntry{
				ID:      operation.ID,
				Kind:    operations.Kind(operation.Kind),
				Target:  firstNonEmpty(operation.Target, "-"),
				State:   state,
				Attempt: operation.Attempts,
				Updated: humanize.Time(operation.UpdatedAt),
				Message: message,
			})
		}

		opts.remoteSvcs = make([]ServiceEntry, 0, len(status.Services))
		for _, service := range status.Services {
			machines := "-"
			if len(service.Machines) > 0 {
				machines = strings.Join(service.Machines, ",")
			}

			lastHealthy := "-"
			if !service.LastHealthy.IsZero() {
				lastHealthy = humanize.Time(service.LastHealthy)
			}

			updated := "-"
			if !service.UpdatedAt.IsZero() {
				updated = humanize.Time(service.UpdatedAt)
			}

			opts.remoteSvcs = append(opts.remoteSvcs, ServiceEntry{
				Name:        firstNonEmpty(service.Name, "-"),
				Strategy:    firstNonEmpty(service.Strategy, "-"),
				Phase:       firstNonEmpty(service.Phase, "-"),
				Ready:       service.Ready,
				Desired:     maxInt(service.Desired, 0),
				Machines:    machines,
				Message:     firstNonEmpty(strings.TrimSpace(service.Message), "-"),
				LastError:   firstNonEmpty(strings.TrimSpace(service.LastError), "-"),
				LastHealthy: lastHealthy,
				Updated:     updated,
			})
		}

		for _, machine := range status.Machines {
			machineState := parseMachineState(machine.State)
			if !opts.ShowAll && machineState != machineapi.MachineStateRunning {
				continue
			}

			endpoint := launchEndpointFromPortString(machine.Ports, controlPlaneHost(ctx, status.Nodes))

			items = append(items, PsEntry{
				ID:         machine.ID,
				Name:       machine.Name,
				Kernel:     machine.Kernel,
				Args:       machine.Args,
				Created:    humanize.Time(machine.CreatedAt),
				State:      machineState,
				Mem:        machine.Mem,
				Ports:      machine.Ports,
				Service:    endpoint.Service,
				PublicPort: endpoint.PublicPort,
				URL:        endpoint.URL,
				Pid:        machine.Pid,
				Arch:       machine.Arch,
				Plat:       machine.Plat,
				IPs:        machine.IPs,
			})
		}

		return items, nil
	}

	platform := mplatform.PlatformUnknown
	var controller machineapi.MachineService

	if opts.platform == "all" {
		controller, err = mplatform.NewMachineV1alpha1ServiceIterator(ctx)
	} else {
		if opts.platform == "" || opts.platform == "auto" {
			platform, _, err = mplatform.Detect(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			platform, ok = mplatform.PlatformsByName()[opts.platform]
			if !ok {
				return nil, fmt.Errorf("unknown platform driver: %s", opts.platform)
			}
		}

		strategy, ok := mplatform.Strategies()[platform]
		if !ok {
			return nil, fmt.Errorf("unsupported platform driver: %s (contributions welcome!)", platform.String())
		}

		controller, err = strategy.NewMachineV1alpha1(ctx)
	}
	if err != nil {
		return nil, err
	}

	machines, err := controller.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return nil, err
	}

	for _, machine := range machines.Items {
		if !opts.ShowAll && machine.Status.State != machineapi.MachineStateRunning {
			continue
		}
		entry := PsEntry{
			ID:      string(machine.UID),
			Name:    machine.Name,
			Args:    strings.Join(machine.Spec.ApplicationArgs, " "),
			Kernel:  machine.Spec.Kernel,
			State:   machine.Status.State,
			Mem:     machine.Spec.Resources.Requests.Memory().String(),
			Created: humanize.Time(machine.ObjectMeta.CreationTimestamp.Time),
			Arch:    machine.Spec.Architecture,
			Pid:     machine.Status.Pid,
			Plat:    machine.Spec.Platform,
			IPs:     []string{},
		}

		if machine.Status.State == machineapi.MachineStateRunning {
			entry.Ports = machine.Spec.Ports.String()
			endpoint := launchEndpointFromMachinePorts(machine.Spec.Ports, "127.0.0.1")
			entry.Service = endpoint.Service
			entry.PublicPort = endpoint.PublicPort
			entry.URL = endpoint.URL
		}

		for _, net := range machine.Spec.Networks {
			for _, iface := range net.Interfaces {
				entry.IPs = append(entry.IPs, iface.Spec.CIDR)
			}
		}

		items = append(items, entry)
	}

	return items, nil
}

func (opts *PsOptions) PrintPsTable(ctx context.Context, items []PsEntry) error {
	err := iostreams.G(ctx).StartPager()
	if err != nil {
		log.G(ctx).Errorf("error starting pager: %v", err)
	}

	defer iostreams.G(ctx).StopPager()

	cs := iostreams.G(ctx).ColorScheme()
	ops, err := opts.operationEntries(ctx, items)
	if err != nil {
		log.G(ctx).WithError(err).Debug("could not read operation status")
	}

	table, err := tableprinter.NewTablePrinter(ctx,
		tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
		tableprinter.WithOutputFormatFromString(opts.Output),
	)
	if err != nil {
		return err
	}

	// Header row
	if opts.Long {
		table.AddField("MACHINE ID", cs.Bold)
	}
	table.AddField("NAME", cs.Bold)
	table.AddField("KERNEL", cs.Bold)
	table.AddField("ARGS", cs.Bold)
	table.AddField("CREATED", cs.Bold)
	table.AddField("STATUS", cs.Bold)
	table.AddField("MEM", cs.Bold)
	table.AddField("PORTS", cs.Bold)
	table.AddField("SERVICE", cs.Bold)
	table.AddField("PUBLIC PORT", cs.Bold)
	table.AddField("URL", cs.Bold)
	if opts.Long {
		table.AddField("IP", cs.Bold)
		table.AddField("PID", cs.Bold)
	}
	table.AddField("PLAT", cs.Bold)
	if opts.Long {
		table.AddField("ARCH", cs.Bold)
	}
	table.EndRow()

	if config.G[config.KraftKit](ctx).NoColor {
		MachineStateColor = MachineStateColorNil
		OperationStateColor = OperationStateColorNil
	}

	if opts.Output == "table" && len(ops) > 0 {
		opTable, err := tableprinter.NewTablePrinter(ctx,
			tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
			tableprinter.WithOutputFormatFromString(opts.Output),
		)
		if err != nil {
			return err
		}

		opTable.AddField("OPERATION", cs.Bold)
		opTable.AddField("KIND", cs.Bold)
		opTable.AddField("TARGET", cs.Bold)
		opTable.AddField("STATUS", cs.Bold)
		opTable.AddField("ATTEMPTS", cs.Bold)
		opTable.AddField("UPDATED", cs.Bold)
		opTable.AddField("MESSAGE", cs.Bold)
		opTable.EndRow()

		for _, op := range ops {
			statusLabel, statusColor := operationDisplay(op)
			opTable.AddField(op.ID, nil)
			opTable.AddField(string(op.Kind), nil)
			opTable.AddField(op.Target, nil)
			opTable.AddField(statusLabel, statusColor)
			opTable.AddField(fmt.Sprintf("%d", maxInt(op.Attempt, 1)), nil)
			opTable.AddField(op.Updated, nil)
			opTable.AddField(op.Message, nil)
			opTable.EndRow()
		}

		if err := opTable.Render(iostreams.G(ctx).Out); err != nil {
			return err
		}

		fmt.Fprintln(iostreams.G(ctx).Out)
	}

	if opts.Output == "table" && len(opts.remoteSvcs) > 0 {
		svcTable, err := tableprinter.NewTablePrinter(ctx,
			tableprinter.WithMaxWidth(iostreams.G(ctx).TerminalWidth()),
			tableprinter.WithOutputFormatFromString(opts.Output),
		)
		if err != nil {
			return err
		}

		svcTable.AddField("SERVICE", cs.Bold)
		svcTable.AddField("STRATEGY", cs.Bold)
		svcTable.AddField("PHASE", cs.Bold)
		svcTable.AddField("READY", cs.Bold)
		svcTable.AddField("MACHINES", cs.Bold)
		svcTable.AddField("MESSAGE", cs.Bold)
		svcTable.AddField("LAST ERROR", cs.Bold)
		svcTable.AddField("LAST HEALTHY", cs.Bold)
		svcTable.AddField("UPDATED", cs.Bold)
		svcTable.EndRow()

		for _, svc := range opts.remoteSvcs {
			svcTable.AddField(svc.Name, nil)
			svcTable.AddField(svc.Strategy, nil)
			svcTable.AddField(svc.Phase, nil)
			svcTable.AddField(fmt.Sprintf("%d/%d", svc.Ready, svc.Desired), nil)
			svcTable.AddField(svc.Machines, nil)
			svcTable.AddField(svc.Message, nil)
			svcTable.AddField(svc.LastError, nil)
			svcTable.AddField(svc.LastHealthy, nil)
			svcTable.AddField(svc.Updated, nil)
			svcTable.EndRow()
		}

		if err := svcTable.Render(iostreams.G(ctx).Out); err != nil {
			return err
		}

		fmt.Fprintln(iostreams.G(ctx).Out)
	}

	for _, item := range items {
		if opts.Long {
			table.AddField(item.ID, nil)
		}
		table.AddField(item.Name, nil)
		table.AddField(item.Kernel, nil)
		table.AddField(item.Args, nil)
		table.AddField(item.Created, nil)
		table.AddField(item.State.String(), MachineStateColor[item.State])
		table.AddField(item.Mem, nil)
		table.AddField(item.Ports, nil)
		table.AddField(item.Service, nil)
		table.AddField(item.PublicPort, nil)
		table.AddField(item.URL, nil)
		if opts.Long {
			table.AddField(strings.Join(item.IPs, ","), nil)
			table.AddField(fmt.Sprintf("%d", item.Pid), nil)
			table.AddField(item.Plat, nil)
		} else {
			table.AddField(fmt.Sprintf("%s/%s", item.Plat, item.Arch), nil)
		}
		if opts.Long {
			table.AddField(item.Arch, nil)
		}
		table.EndRow()
	}

	return table.Render(iostreams.G(ctx).Out)
}

func (opts *PsOptions) operationEntries(ctx context.Context, items []PsEntry) ([]OperationEntry, error) {
	if len(opts.remoteOps) > 0 {
		return opts.remoteOps, nil
	}

	store, err := operations.NewStore(ctx)
	if err != nil {
		return nil, err
	}

	records, err := store.List(20)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil
	}

	machineStates := map[string]machineapi.MachineState{}
	for _, item := range items {
		machineStates[item.Name] = item.State
		machineStates[item.ID] = item.State
	}

	entries := make([]OperationEntry, 0, len(records))
	for _, record := range records {
		target := record.Machine
		if target == "" && len(record.Targets) > 0 {
			target = strings.Join(record.Targets, ",")
		}
		if target == "" {
			target = "-"
		}

		state := deriveOperationState(record, machineStates)
		message := strings.TrimSpace(record.Message)
		if record.Error != "" {
			message = record.Error
		}
		if message == "" {
			message = "-"
		}

		if staleOperationRecord(record, state, machineStates) {
			state = operations.StateFailed
			lowerMessage := strings.ToLower(strings.TrimSpace(message))
			if message == "-" || strings.EqualFold(strings.TrimSpace(message), "resolving deployment input") || strings.HasPrefix(lowerMessage, "deployment submitted for ") {
				message = "stale operation record (machine missing after restart or interrupted deploy)"
			}
		}

		entries = append(entries, OperationEntry{
			ID:      record.ID,
			Kind:    record.Kind,
			Target:  target,
			State:   state,
			Attempt: record.Attempts,
			Updated: humanize.Time(record.UpdatedAt),
			Message: message,
		})
	}

	return entries, nil
}

func staleOperationRecord(record operations.Record, state operations.State, machineStates map[string]machineapi.MachineState) bool {
	if record.Kind != operations.KindDeploy {
		return false
	}
	if state != operations.StateRunning && state != operations.StatePending && state != operations.StateSubmitted {
		return false
	}
	machineName := strings.TrimSpace(record.Machine)
	if machineName != "" {
		if _, ok := machineStates[machineName]; ok {
			return false
		}
	}

	updated := record.UpdatedAt
	if updated.IsZero() {
		updated = record.CreatedAt
	}
	if updated.IsZero() {
		return false
	}

	return time.Since(updated) > operationStaleAfter
}

func parseMachineState(value string) machineapi.MachineState {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(machineapi.MachineStateCreated):
		return machineapi.MachineStateCreated
	case string(machineapi.MachineStateFailed):
		return machineapi.MachineStateFailed
	case string(machineapi.MachineStateRestarting):
		return machineapi.MachineStateRestarting
	case string(machineapi.MachineStateRunning):
		return machineapi.MachineStateRunning
	case string(machineapi.MachineStatePaused):
		return machineapi.MachineStatePaused
	case string(machineapi.MachineStateSuspended):
		return machineapi.MachineStateSuspended
	case string(machineapi.MachineStateExited):
		return machineapi.MachineStateExited
	case string(machineapi.MachineStateErrored):
		return machineapi.MachineStateErrored
	default:
		return machineapi.MachineStateUnknown
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func deriveOperationState(record operations.Record, machineStates map[string]machineapi.MachineState) operations.State {
	if record.State == operations.StateSucceeded || record.State == operations.StateFailed {
		return record.State
	}

	switch record.Kind {
	case operations.KindDeploy:
		if record.Machine == "" {
			return record.State
		}

		state, ok := machineStates[record.Machine]
		if !ok {
			return record.State
		}

		switch state {
		case machineapi.MachineStateRunning, machineapi.MachineStateExited:
			return operations.StateSucceeded
		case machineapi.MachineStateFailed, machineapi.MachineStateErrored:
			return operations.StateFailed
		default:
			return operations.StateRunning
		}

	case operations.KindDestroy:
		if len(record.Targets) == 0 {
			return record.State
		}

		for _, target := range record.Targets {
			if _, ok := machineStates[target]; ok {
				return operations.StateRunning
			}
		}

		return operations.StateSucceeded
	}

	return record.State
}

func operationDisplay(op OperationEntry) (string, colorFunc) {
	switch op.Kind {
	case operations.KindDeploy:
		switch op.State {
		case operations.StateFailed:
			return "failed", OperationStateColor[operations.StateFailed]
		case operations.StateSucceeded:
			return "running", OperationStateColor[operations.StateSucceeded]
		default:
			return "deploying", OperationStateColor[operations.StateRunning]
		}

	case operations.KindDestroy:
		switch op.State {
		case operations.StateFailed:
			return "failed", OperationStateColor[operations.StateFailed]
		case operations.StateSucceeded:
			return "destroyed", OperationStateColor[operations.StateSucceeded]
		default:
			return "destroying", OperationStateColor[operations.StateRunning]
		}
	}

	label := strings.TrimSpace(string(op.State))
	if label == "" {
		label = string(operations.StatePending)
	}

	return label, OperationStateColor[op.State]
}

type launchCandidate struct {
	Host        string
	HostPort    int
	MachinePort int
	Protocol    string
}

type launchEndpoint struct {
	Service    string
	PublicPort string
	URL        string
}

func launchEndpointFromMachinePorts(ports machineapi.MachinePorts, fallbackHost string) launchEndpoint {
	candidates := make([]launchCandidate, 0, len(ports))
	for _, port := range ports {
		candidates = append(candidates, launchCandidate{
			Host:        strings.TrimSpace(port.HostIP),
			HostPort:    int(port.HostPort),
			MachinePort: int(port.MachinePort),
			Protocol:    strings.ToLower(strings.TrimSpace(string(port.Protocol))),
		})
	}

	return launchEndpointFromCandidates(candidates, fallbackHost)
}

func launchEndpointFromPortString(ports, fallbackHost string) launchEndpoint {
	candidates := []launchCandidate{}
	for _, token := range strings.Split(ports, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		left, right, ok := strings.Cut(token, "->")
		if !ok {
			continue
		}

		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)

		colon := strings.LastIndex(left, ":")
		if colon <= 0 || colon >= len(left)-1 {
			continue
		}

		host := strings.TrimSpace(left[:colon])
		hostPort, err := strconv.Atoi(strings.TrimSpace(left[colon+1:]))
		if err != nil || hostPort <= 0 {
			continue
		}

		target, proto, _ := strings.Cut(right, "/")
		target = strings.TrimSpace(target)
		machinePort := 0
		if p, err := strconv.Atoi(target); err == nil {
			machinePort = p
		}

		candidates = append(candidates, launchCandidate{
			Host:        host,
			HostPort:    hostPort,
			MachinePort: machinePort,
			Protocol:    strings.ToLower(strings.TrimSpace(proto)),
		})
	}

	return launchEndpointFromCandidates(candidates, fallbackHost)
}

func launchEndpointFromCandidates(candidates []launchCandidate, fallbackHost string) launchEndpoint {
	if len(candidates) == 0 {
		return launchEndpoint{
			Service:    "-",
			PublicPort: "-",
			URL:        "-",
		}
	}

	bestIndex := -1
	bestScore := 1 << 30
	for index, candidate := range candidates {
		if candidate.HostPort <= 0 {
			continue
		}

		proto := strings.TrimSpace(candidate.Protocol)
		if proto != "" && proto != "tcp" {
			continue
		}

		score := launchCandidateScore(candidate)
		if score < bestScore {
			bestScore = score
			bestIndex = index
		}
	}

	if bestIndex < 0 {
		return launchEndpoint{
			Service:    "-",
			PublicPort: "-",
			URL:        "-",
		}
	}

	selected := candidates[bestIndex]
	host := normalizeHost(selected.Host, fallbackHost)
	if host == "" {
		host = "127.0.0.1"
	}
	service := fmt.Sprintf("%d/tcp", selected.MachinePort)
	if selected.MachinePort <= 0 {
		service = "-"
	}
	publicPort := fmt.Sprintf("%s:%d", host, selected.HostPort)

	scheme := "http"
	if selected.HostPort == 443 || selected.MachinePort == 443 {
		scheme = "https"
	}

	endpoint := launchEndpoint{
		Service:    service,
		PublicPort: publicPort,
	}

	if (scheme == "http" && selected.HostPort == 80) || (scheme == "https" && selected.HostPort == 443) {
		endpoint.URL = fmt.Sprintf("%s://%s", scheme, host)
		return endpoint
	}

	endpoint.URL = fmt.Sprintf("%s://%s:%d", scheme, host, selected.HostPort)
	return endpoint
}

func launchCandidateScore(candidate launchCandidate) int {
	switch candidate.HostPort {
	case 443:
		return 0
	case 80:
		return 1
	case 8080:
		return 2
	case 3000:
		return 3
	case 5173:
		return 4
	case 5000:
		return 5
	default:
		return 1000 + candidate.HostPort
	}
}

func normalizeHost(host, fallbackHost string) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = strings.TrimSpace(fallbackHost)
	}

	if host == "" {
		return ""
	}

	if parsed := net.ParseIP(host); parsed != nil {
		return parsed.String()
	}

	host = strings.Trim(host, "[]")
	return host
}

func controlPlaneHost(ctx context.Context, nodes []controlplaneapi.Node) string {
	endpoint := strings.TrimSpace(os.Getenv("UNIKCTL_CONTROL_PLANE_URL"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(config.G[config.KraftKit](ctx).ControlPlane.URL)
	}

	if endpoint != "" {
		if parsed, err := url.Parse(endpoint); err == nil {
			host := strings.TrimSpace(parsed.Hostname())
			if host != "" {
				return host
			}
		}
	}

	for _, node := range nodes {
		address := strings.TrimSpace(node.Address)
		if address == "" {
			continue
		}

		if host, _, err := net.SplitHostPort(address); err == nil {
			host = strings.TrimSpace(host)
			if host != "" {
				return host
			}
			continue
		}

		if parsed, err := url.Parse("http://" + address); err == nil {
			host := strings.TrimSpace(parsed.Hostname())
			if host != "" {
				return host
			}
		}
	}

	return "127.0.0.1"
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}
