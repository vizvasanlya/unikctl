// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package firecracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	zip "api.zip"
	"github.com/acorn-io/baaah/pkg/merr"
	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/fsnotify/fsnotify"
	goprocess "github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	machinev1alpha1 "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/config"
	"unikctl.sh/exec"
	"unikctl.sh/internal/logtail"
	"unikctl.sh/internal/run"
	"unikctl.sh/log"
	"unikctl.sh/machine/name"
	"unikctl.sh/machine/network/macaddr"
	"unikctl.sh/machine/resources"
	"unikctl.sh/unikraft/export/v0/posixenviron"
	"unikctl.sh/unikraft/export/v0/ukargparse"
	"unikctl.sh/unikraft/export/v0/uknetdev"
	"unikctl.sh/unikraft/export/v0/vfscore"
)

const (
	FirecrackerBin         = "firecracker"
	DefaultClientTimout    = time.Second * 5
	FirecrackerMemoryScale = 1024 * 1024
)

const (
	defaultSnapshotStateName = "snapshot.state"
	defaultSnapshotMemName   = "snapshot.mem"
	defaultSnapshotMetaName  = "snapshot.json"
)

type snapshotMetadata struct {
	Machine        string    `json:"machine"`
	StatePath      string    `json:"state_path"`
	MemoryPath     string    `json:"memory_path"`
	CreatedAt      time.Time `json:"created_at"`
	SnapshotNanos  int64     `json:"snapshot_nanos"`
	ResumeNanos    int64     `json:"resume_nanos,omitempty"`
	Paused         bool      `json:"paused"`
	ReferenceCount int       `json:"reference_count"`
	LastUsedAt     time.Time `json:"last_used_at"`
}

// machineV1alpha1Service ...
type machineV1alpha1Service struct {
	timeout time.Duration
	debug   bool
}

// NewMachineV1alpha1Service implements mdriver.NewDriverConstructor
func NewMachineV1alpha1Service(ctx context.Context, opts ...any) (machinev1alpha1.MachineService, error) {
	service := machineV1alpha1Service{}

	for _, opt := range opts {
		qopt, ok := opt.(MachineServiceV1alpha1Option)
		if !ok {
			panic("cannot apply non-MachineServiceV1alpha1Option type methods")
		}

		if err := qopt(&service); err != nil {
			return nil, err
		}
	}

	if service.timeout == 0 {
		service.timeout = DefaultClientTimout
	}

	return &service, nil
}

// Create implements unikctl.sh/api/machine/v1alpha1.MachineService.Create
func (service *machineV1alpha1Service) Create(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	// Start with fail-safe checks for unsupported specification declarations.
	if len(machine.Spec.Ports) > 0 {
		return machine, fmt.Errorf("kraftkit does not yet support port forwarding to firecracker (contributions welcome): please use a network instead")
	}

	if machine.Status.KernelPath == "" {
		return machine, fmt.Errorf("cannot create firecracker instance without kernel")
	}

	if machine.Spec.Emulation {
		return machine, fmt.Errorf("cannot create firecracker instance with emulation")
	}

	if machine.ObjectMeta.UID == "" {
		machineID, err := name.NewRandomMachineID()
		if err != nil {
			return nil, fmt.Errorf("could not generate machine UID: %w", err)
		}

		machine.ObjectMeta.UID = types.UID(machineID.ShortString())
	}

	machine.Status.State = machinev1alpha1.MachineStateUnknown

	if len(machine.Status.StateDir) == 0 {
		machine.Status.StateDir = filepath.Join(config.G[config.KraftKit](ctx).RuntimeDir, string(machine.ObjectMeta.UID))
	}

	if err := os.MkdirAll(machine.Status.StateDir, fs.ModeSetgid|0o775); err != nil {
		return machine, err
	}

	// Ensure the directory and its contents are owned by the original user when running under sudo
	if err := config.ChownToUserRecursive(machine.Status.StateDir); err != nil {
		return machine, err
	}

	// Set and create the log file for this machine
	if len(machine.Status.LogFile) == 0 {
		machine.Status.LogFile = filepath.Join(machine.Status.StateDir, "vm.log")
	}

	var fstab []string

	for _, vol := range machine.Spec.Volumes {
		switch vol.Spec.Driver {
		case "initrd":
			fstab = append(fstab, vfscore.NewFstabEntry(
				"initrd0",
				vol.Spec.Destination,
				"extract",
				"",
				"",
				"",
			).String())
		default:
			return machine, fmt.Errorf("unsupported Firecracker volume driver: %v", vol.Spec.Driver)
		}
	}

	if err := resources.ApplyDefaultsAndValidate(
		&machine.Spec.Resources,
		resources.DefaultCPURequest,
		resources.DefaultMemoryRequest,
	); err != nil {
		machine.Status.State = machinev1alpha1.MachineStateFailed
		return machine, err
	}

	fcLogFile := filepath.Join(machine.Status.StateDir, "vmm.log")
	fi, err := os.Create(fcLogFile)
	if err != nil {
		return machine, err
	}

	fi.Close()

	fccfg := FirecrackerConfig{
		SocketPath: filepath.Join(machine.Status.StateDir, "vmm.sock"),
		LogPath:    fcLogFile,
		Memory:     machine.Spec.Resources.Requests.Memory().String(),
		CPU:        machine.Spec.Resources.Requests.Cpu().String(),
	}

	defer func() {
		if err != nil {
			machine.Status.State = machinev1alpha1.MachineStateFailed
		}
	}()

	// If you fork and replace the stdout file descriptor with an fd of a log file
	// and then execv firecracker, you don't have to care about collecting the
	// logs
	logFile, err := os.Create(machine.Status.LogFile)
	if err != nil {
		return machine, err
	}

	defer logFile.Close()

	machine.Status.PlatformConfig = &fccfg

	e, err := exec.NewExecutable(FirecrackerBin, ExecConfig{
		Id:      string(machine.UID),
		ApiSock: fccfg.SocketPath,
	})
	if err != nil {
		return machine, fmt.Errorf("could not prepare firecracker executable: %v", err)
	}

	process, err := exec.NewProcessFromExecutable(e,
		exec.WithStdout(logFile),
		exec.WithDetach(true),
	)
	if err != nil {
		return machine, fmt.Errorf("could not prepare firecracker process: %v", err)
	}

	machine.CreationTimestamp = metav1.NewTime(time.Now())

	// Pre-emptively prepare inotify on the state directory so we can wait until
	// the socket file has been created.  This is an indicator that firecracker
	// process has initialized into a running state.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return machine, err
	}
	defer watcher.Close()

	if err := watcher.Add(machine.Status.StateDir); err != nil {
		return machine, err
	}

	// Start and also wait for the process to be released, this ensures the
	// program is actively being executed.
	if err := process.Start(ctx); err != nil {
		return machine, fmt.Errorf("could not start and wait for firecracker process: %v", err)
	}

	// Wait for the socket file to be created
watch:
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				continue
			}
			if event.Name == fccfg.SocketPath {
				break watch
			}
		case <-ctx.Done():
			err = ctx.Err()
			break watch
		}
	}

	pid, err := process.Pid()
	if err != nil {
		return machine, fmt.Errorf("could not get firecracker pid: %v", err)
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)

	kernelArgs, err := ukargparse.Parse(machine.Spec.KernelArgs...)
	if err != nil {
		return machine, err
	}

	if len(fstab) > 0 {
		kernelArgs = append(kernelArgs,
			vfscore.ParamVfsFstab.WithValue(fstab),
		)
	}

	var environ []string
	for k, v := range machine.Spec.Env {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}

	if len(environ) > 0 {
		kernelArgs = append(kernelArgs,
			posixenviron.ParamEnvVars.WithValue(environ),
		)
	}

	if len(machine.Spec.Networks) > 0 {
		// Start MAC addresses iteratively.  Each interface will have the last
		// hexdecimal byte increase by 1 starting at 1, allowing for easy-to-spot
		// interface IDs from the MAC address.  The return value below returns `:00`
		// as the last byte.
		startMac, err := macaddr.GenerateMacAddress(true)
		if err != nil {
			return machine, err
		}

		i := 0 // host network ID.

		// Iterate over each interface of each network interface associated with
		// this machine and attach it as a device.
		for _, network := range machine.Spec.Networks {
			for _, iface := range network.Interfaces {
				mac := iface.Spec.MacAddress
				if mac == "" {
					// Increase the MAC address value by 1 such that we are able to
					// identify interface IDs.
					startMac = macaddr.IncrementMacAddress(startMac)
					mac = startMac.String()
				}

				if _, err := client.PutGuestNetworkInterfaceByID(ctx, network.IfName, &models.NetworkInterface{
					GuestMac:    mac,
					HostDevName: &iface.Spec.IfName,
					IfaceID:     &network.IfName,
				}); err != nil {
					return machine, err
				}

				kernelArgs = append(kernelArgs,
					uknetdev.NewParamIp().WithValue(uknetdev.NetdevIp{
						CIDR:     iface.Spec.CIDR,
						Gateway:  iface.Spec.Gateway,
						DNS0:     iface.Spec.DNS0,
						DNS1:     iface.Spec.DNS1,
						Hostname: iface.Spec.Hostname,
						Domain:   iface.Spec.Domain,
					}),
				)

				// Increment the host network ID for additional interfaces.
				i++
			}
		}
	}

	// TODO(nderjung): This is standard "Unikraft" positional argument syntax
	// (kernel args and application arguments separated with "--").  The resulting
	// string should be standardized through a central function.
	args := []string{filepath.Base(machine.Status.KernelPath)}
	args = append(args, kernelArgs.Strings()...)

	if len(args) > 0 {
		args = append(args, "--")
	}
	args = append(args, machine.Spec.ApplicationArgs...)

	// Set the machine's resource configuration.
	if _, err := client.PutMachineConfiguration(ctx, &models.MachineConfiguration{
		VcpuCount:  firecracker.Int64(machine.Spec.Resources.Requests.Cpu().Value()),
		MemSizeMib: firecracker.Int64(machine.Spec.Resources.Requests.Memory().Value() / FirecrackerMemoryScale),
	}); err != nil {
		return machine, err
	}

	// Set the boot source configuration.
	if _, err := client.PutGuestBootSource(ctx, &models.BootSource{
		KernelImagePath: &machine.Status.KernelPath,
		InitrdPath:      machine.Status.InitrdPath,
		BootArgs:        run.BootArgsPrepare(args...),
	}); err != nil {
		return machine, err
	}

	// Set the logger information.
	if service.debug {
		if _, err := client.PutLogger(ctx, &models.Logger{
			Level:         firecracker.String("Debug"),
			LogPath:       firecracker.String(filepath.Join(machine.Status.StateDir, "vmm.log")),
			ShowLevel:     firecracker.Bool(true),
			ShowLogOrigin: firecracker.Bool(true),
		}); err != nil {
			return machine, err
		}
	}

	machine.Status.Pid = int32(pid)
	machine.Status.State = machinev1alpha1.MachineStateCreated

	return machine, nil
}

func getFirecrackerConfigFromPlatformConfig(platformConfig interface{}) (*FirecrackerConfig, error) {
	fccfgptr, ok := platformConfig.(*FirecrackerConfig)
	if ok {
		return fccfgptr, nil
	}

	fccfg, ok := platformConfig.(FirecrackerConfig)
	if ok {
		return &fccfg, nil
	}

	return nil, fmt.Errorf("could not cast firecracker platform config from store")
}

// Update implements unikctl.sh/api/machine/v1alpha1.MachineService
func (service *machineV1alpha1Service) Update(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	panic("not implemented: unikctl.sh/machine/firecracker.machineV1alpha1Service.Update")
}

// Watch implements unikctl.sh/api/machine/v1alpha1.MachineService
func (service *machineV1alpha1Service) Watch(ctx context.Context, machine *machinev1alpha1.Machine) (chan *machinev1alpha1.Machine, chan error, error) {
	events := make(chan *machinev1alpha1.Machine)
	errs := make(chan error)

	go service.watch(ctx, machine, &events, &errs)

	return events, errs, nil
}

func (service *machineV1alpha1Service) watch(ctx context.Context, machine *machinev1alpha1.Machine, events *chan *machinev1alpha1.Machine, errs *chan error) {
	for {
		select {
		case <-ctx.Done():
			log.G(ctx).Info("context cancelled (watch)")
			*errs <- ctx.Err()
			return
		default:
			process, err := os.FindProcess(int(machine.Status.Pid))
			if err != nil {
				return
			}

			state, err := process.Wait()
			if err != nil {
				*errs <- err
				return
			}

			if state.Exited() {
				machine.Status.State = machinev1alpha1.MachineStateExited
				machine.Status.ExitCode = state.ExitCode()
			}

			*events <- machine
		}
	}
}

// Start implements unikctl.sh/api/machine/v1alpha1.MachineService
func (service *machineV1alpha1Service) Start(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)
	action := models.InstanceActionInfoActionTypeInstanceStart
	info := models.InstanceActionInfo{
		ActionType: &action,
	}

	if _, err := client.CreateSyncAction(ctx, &info); err != nil {
		return machine, err
	}

	machine.Status.State = machinev1alpha1.MachineStateRunning
	machine.Status.StartedAt = time.Now()

	return machine, nil
}

// Pause implements unikctl.sh/api/machine/v1alpha1.MachineService
func (service *machineV1alpha1Service) Pause(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)
	state := models.VMStatePaused
	if _, err := client.PatchVM(ctx, &models.VM{State: &state}); err != nil {
		return machine, err
	}

	machine.Status.State = machinev1alpha1.MachineStatePaused
	return machine, nil
}

// Logs implements unikctl.sh/api/machine/v1alpha1.MachineService
func (service *machineV1alpha1Service) Logs(ctx context.Context, machine *machinev1alpha1.Machine) (chan string, chan error, error) {
	return logtail.NewLogTail(ctx, machine.Status.LogFile)
}

// Get implements unikctl.sh/api/machine/v1alpha1/MachineService.Get
func (service *machineV1alpha1Service) Get(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	state := machinev1alpha1.MachineStateUnknown
	savedState := machine.Status.State

	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	// Backfill missing requests from platform config without mutating explicit
	// user-provided resources.
	if err := resources.BackfillMissingFromPlatform(&machine.Spec.Resources, fccfg.CPU, fccfg.Memory); err != nil {
		return machine, err
	}

	// Check if the process is alive, which ultimately indicates to us whether we
	// able to speak to the exposed QMP socket
	activeProcess := false
	if process, err := goprocess.NewProcess(machine.Status.Pid); err == nil {
		activeProcess, err = process.IsRunning()
		if err != nil {
			state = machinev1alpha1.MachineStateExited
		}
	}

	exitedAt := machine.Status.ExitedAt
	exitCode := machine.Status.ExitCode

	defer func() {
		if exitCode >= 0 && machine.Status.ExitedAt.IsZero() {
			exitedAt = time.Now()
		}

		// Update the machine config with the latest values if they are different from
		// what we have on record
		if machine.Status.ExitedAt != exitedAt || machine.Status.ExitCode != exitCode {
			machine.Status.ExitedAt = exitedAt
			machine.Status.ExitCode = exitCode
		}

		// Set the start time to now if it was not previously set
		if machine.Status.StartedAt.IsZero() && state == machinev1alpha1.MachineStateRunning {
			machine.Status.StartedAt = time.Now()
		}

		// Finally, save the state if it is different from the what we have on
		// record
		if state != savedState {
			machine.Status.State = state
		}
	}()

	if !activeProcess {
		state = machinev1alpha1.MachineStateExited
		if savedState == machinev1alpha1.MachineStateRunning {
			exitCode = 1
		}
		return machine, nil
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)

	// Grab the actual state of the machine by querying the API socket
	ctx, cancel := context.WithTimeout(ctx, service.timeout)
	info, err := client.GetInstanceInfo(ctx)
	if err != nil {
		cancel()
		// We cannot amend the status at this point, even if the process is
		// alive, since it is not an indicator of the state of the VM, only of the
		// VMM.  So we return what we already know via LookupMachineConfig.
		return machine, fmt.Errorf("could not query machine status via API socket: %v", err)
	}

	cancel()

	// Map the Firecracker state to supported machine states
	switch *info.Payload.State {
	case models.InstanceInfoStateNotStarted:
		state = machinev1alpha1.MachineStateCreated
		exitCode = -1

	case models.InstanceInfoStateRunning:
		state = machinev1alpha1.MachineStateRunning
		exitCode = -1

	case models.InstanceInfoStatePaused:
		state = machinev1alpha1.MachineStatePaused
		exitCode = -1
	}

	machine.Status.PlatformConfig = fccfg

	return machine, nil
}

// List implements unikctl.sh/api/machine/v1alpha1.MachineService.List
func (service *machineV1alpha1Service) List(ctx context.Context, machines *machinev1alpha1.MachineList) (*machinev1alpha1.MachineList, error) {
	cached := machines.Items
	machines.Items = []zip.Object[machinev1alpha1.MachineSpec, machinev1alpha1.MachineStatus]{}

	// Iterate through each machine and grab the latest status
	for _, machine := range cached {
		machine, err := service.Get(ctx, &machine)
		if err != nil {
			machines.Items = cached
			return machines, err
		}

		machines.Items = append(machines.Items, *machine)
	}

	return machines, nil
}

// Stop implements unikctl.sh/api/machine/v1alpha1.MachineService.Stop
func (service *machineV1alpha1Service) Stop(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	if machine.Status.State == machinev1alpha1.MachineStateExited {
		return machine, nil
	}

	process, err := goprocess.NewProcess(machine.Status.Pid)
	if err != nil {
		return machine, err
	}

	if err := process.Terminate(); err != nil {
		return machine, err
	}

	machine.Status.State = machinev1alpha1.MachineStateExited
	machine.Status.ExitedAt = time.Now()

	return machine, nil
}

// Resume resumes a paused Firecracker microVM.
func (service *machineV1alpha1Service) Resume(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)
	state := models.VMStateResumed
	startedAt := time.Now().UTC()
	if _, err := client.PatchVM(ctx, &models.VM{State: &state}); err != nil {
		return machine, err
	}

	machine.Status.State = machinev1alpha1.MachineStateRunning
	if machine.Status.StartedAt.IsZero() {
		machine.Status.StartedAt = startedAt
	}

	_ = updateSnapshotResumeLatency(fccfg)
	return machine, nil
}

// Snapshot captures a full snapshot and records metadata in the state directory.
func (service *machineV1alpha1Service) Snapshot(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	if err := os.MkdirAll(machine.Status.StateDir, 0o755); err != nil {
		return machine, err
	}

	statePath := filepath.Join(machine.Status.StateDir, defaultSnapshotStateName)
	memPath := filepath.Join(machine.Status.StateDir, defaultSnapshotMemName)
	metaPath := filepath.Join(machine.Status.StateDir, defaultSnapshotMetaName)

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)
	started := time.Now().UTC()
	params := &models.SnapshotCreateParams{
		MemFilePath:  firecracker.String(memPath),
		SnapshotPath: firecracker.String(statePath),
		SnapshotType: models.SnapshotCreateParamsSnapshotTypeFull,
	}
	if _, err := client.CreateSnapshot(ctx, params); err != nil {
		return machine, err
	}

	metadata := snapshotMetadata{
		Machine:        machine.Name,
		StatePath:      statePath,
		MemoryPath:     memPath,
		CreatedAt:      started,
		SnapshotNanos:  time.Since(started).Nanoseconds(),
		Paused:         machine.Status.State == machinev1alpha1.MachineStatePaused,
		ReferenceCount: 1,
		LastUsedAt:     time.Now().UTC(),
	}
	if err := writeSnapshotMetadata(metaPath, metadata); err != nil {
		return machine, err
	}

	fccfg.SnapshotPath = statePath
	fccfg.SnapshotMem = memPath
	fccfg.SnapshotMeta = metaPath
	machine.Status.PlatformConfig = fccfg
	return machine, nil
}

// Restore restores a Firecracker microVM from a previously captured snapshot.
func (service *machineV1alpha1Service) Restore(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	if strings.TrimSpace(fccfg.SnapshotPath) == "" || strings.TrimSpace(fccfg.SnapshotMem) == "" {
		return machine, fmt.Errorf("snapshot paths are not configured for machine %s", machine.Name)
	}

	client := firecracker.NewClient(fccfg.SocketPath, logrus.NewEntry(log.G(ctx)), false)
	started := time.Now().UTC()
	params := &models.SnapshotLoadParams{
		MemFilePath:  firecracker.String(fccfg.SnapshotMem),
		SnapshotPath: firecracker.String(fccfg.SnapshotPath),
		ResumeVM:     true,
	}
	if _, err := client.LoadSnapshot(ctx, params); err != nil {
		return machine, err
	}

	machine.Status.State = machinev1alpha1.MachineStateRunning
	if machine.Status.StartedAt.IsZero() {
		machine.Status.StartedAt = started
	}

	if err := updateSnapshotResumeLatency(fccfg); err != nil {
		log.G(ctx).WithError(err).Debug("could not update snapshot resume metadata")
	}
	return machine, nil
}

// Inspect refreshes and returns the machine with latest runtime state.
func (service *machineV1alpha1Service) Inspect(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	return service.Get(ctx, machine)
}

// Delete implements unikctl.sh/api/machine/v1alpha1.MachineService.Delete
func (service *machineV1alpha1Service) Delete(ctx context.Context, machine *machinev1alpha1.Machine) (*machinev1alpha1.Machine, error) {
	fccfg, err := getFirecrackerConfigFromPlatformConfig(machine.Status.PlatformConfig)
	if err != nil {
		return machine, err
	}

	var errs merr.Errors

	errs = append(errs, os.Remove(machine.Status.LogFile))
	errs = append(errs, os.Remove(fccfg.LogPath))
	errs = append(errs, os.RemoveAll(machine.Status.StateDir))

	return nil, errs.Err()
}

func writeSnapshotMetadata(path string, metadata snapshotMetadata) error {
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func updateSnapshotResumeLatency(config *FirecrackerConfig) error {
	if config == nil || strings.TrimSpace(config.SnapshotMeta) == "" {
		return nil
	}

	raw, err := os.ReadFile(config.SnapshotMeta)
	if err != nil {
		return err
	}

	var metadata snapshotMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return err
	}

	metadata.ResumeNanos = time.Since(metadata.CreatedAt).Nanoseconds()
	metadata.LastUsedAt = time.Now().UTC()
	metadata.ReferenceCount++
	return writeSnapshotMetadata(config.SnapshotMeta, metadata)
}
