// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package run

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	"unikctl.sh/cmdfactory"
	"unikctl.sh/config"
	"unikctl.sh/initrd"
	buildcmd "unikctl.sh/internal/cli/unikctl/build"
	"unikctl.sh/internal/cli/unikctl/start"
	"unikctl.sh/internal/controlplaneapi"
	"unikctl.sh/internal/operations"
	"unikctl.sh/internal/runtimeutil"
	"unikctl.sh/internal/set"
	"unikctl.sh/iostreams"
	"unikctl.sh/log"
	mplatform "unikctl.sh/machine/platform"
	"unikctl.sh/packmanager"
	"unikctl.sh/tui/selection"
	ukarch "unikctl.sh/unikraft/arch"
)

type RunOptions struct {
	Architecture   string        `long:"arch" short:"m" usage:"Set the architecture"`
	Detach         bool          `long:"detach" short:"d" usage:"Run unikernel in background"`
	DisableAccel   bool          `long:"disable-acceleration" short:"W" usage:"Disable acceleration of CPU (usually enables TCG)"`
	Env            []string      `long:"env" short:"e" usage:"Set environment variables, int the format key[=value]" split:"false"`
	InitRd         string        `long:"initrd" usage:"Use the specified initrd (readonly)" hidden:"true"`
	IP             string        `long:"ip" usage:"Assign the provided IP address"`
	KeepFileOwners bool          `noattribute:"true"`
	KernelArgs     []string      `long:"kernel-arg" short:"a" usage:"Set additional kernel arguments"`
	Kraftfile      string        `long:"kraftfile" short:"K" usage:"Set an alternative path of the Kraftfile"`
	MacAddress     string        `long:"mac" usage:"Assign the provided MAC address"`
	Memory         string        `long:"memory" short:"M" usage:"Assign memory to the unikernel (K/Ki, M/Mi, G/Gi)" default:"64Mi"`
	Name           string        `long:"name" short:"n" usage:"Name of the instance"`
	Networks       []string      `long:"network" usage:"Attach instance to the provided network, in the format <network>[:ip[/mask][:gw[:dns0[:dns1[:hostname[:domain]]]]]], e.g. kraft0:172.100.0.2"`
	NoStart        bool          `long:"no-start" usage:"Do not start the machine"`
	Platform       string        `noattribute:"true"`
	Ports          []string      `long:"port" short:"p" usage:"Publish a machine's port(s) to the host" split:"false"`
	Prefix         string        `long:"prefix" usage:"Prefix each log line with the given string"`
	PrefixName     bool          `long:"prefix-name" usage:"Prefix each log line with the machine name"`
	Remove         bool          `long:"rm" usage:"Automatically remove the unikernel when it shutsdown"`
	Rootfs         string        `long:"rootfs" usage:"Specify a path to use as root file system (can be volume or initramfs)"`
	RootfsType     initrd.FsType `noattribute:"true"`
	RunAs          string        `long:"as" usage:"Force a specific runner"`
	Runtime        string        `long:"runtime" short:"r" usage:"Set an alternative unikernel runtime"`
	Target         string        `long:"target" short:"t" usage:"Explicitly use the defined project target"`
	Volumes        []string      `long:"volume" short:"v" usage:"Bind a volume to the instance"`
	WithKernelDbg  bool          `long:"symbolic" usage:"Use the debuggable (symbolic) unikernel"`
	Debug          bool          `long:"debug" usage:"Use the debuggable (symbolic) image"`

	workdir           string
	platform          mplatform.Platform
	machineController machineapi.MachineService
	hostPlatform      mplatform.Platform
	hostMode          mplatform.SystemMode
}

type deployProjectConfig struct {
	Deploy struct {
		ServiceName    string `yaml:"service,omitempty"`
		Replicas       int    `yaml:"replicas,omitempty"`
		Strategy       string `yaml:"strategy,omitempty"`
		MaxUnavailable int    `yaml:"max_unavailable,omitempty"`
		MaxSurge       int    `yaml:"max_surge,omitempty"`
		CanaryPercent  int    `yaml:"canary_percent,omitempty"`
		HealthCheck    struct {
			Path            string `yaml:"path,omitempty"`
			Port            int    `yaml:"port,omitempty"`
			IntervalSeconds int    `yaml:"interval_seconds,omitempty"`
			TimeoutSeconds  int    `yaml:"timeout_seconds,omitempty"`
		} `yaml:"health_check,omitempty"`
	} `yaml:"deploy,omitempty"`
}

// Run a Unikraft unikernel virtual machine locally.
func Run(ctx context.Context, opts *RunOptions, args ...string) error {
	if opts == nil {
		opts = &RunOptions{
			hostPlatform: mplatform.PlatformUnknown,
			hostMode:     mplatform.SystemUnknown,
		}
	}

	return opts.Run(ctx, args)
}

func NewCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&RunOptions{}, cobra.Command{
		Short:   "Run a unikernel",
		Use:     "run [FLAGS] PROJECT|PACKAGE|BINARY -- [APP ARGS]",
		Aliases: []string{"r"},
		Long: heredoc.Doc(`
			Run a unikernel virtual machine
		`),
		Example: heredoc.Doc(`
			Run a built target in the current working directory project:
			$ unikctl run

			Run a specific target from a multi-target project at the provided project directory:
			$ unikctl run -t TARGET path/to/project

			Run a specific kernel binary:
			$ unikctl run --arch x86_64 --plat qemu path/to/kernel-x86_64-qemu

			Run a specific kernel binary with 1000 megabytes of memory:
			$ unikctl run --arch x86_64 --plat qemu --memory 1G path/to/kernel-x86_64-qemu

			Run a specific kernel binary with 1024 megabytes of memory:
			$ unikctl run --arch x86_64 --plat qemu --memory 1Gi path/to/kernel-x86_64-qemu

			Run an OCI-compatible unikernel, mapping port 8080 on the host to port 80 in the unikernel:
			$ unikctl run -p 8080:80 ghcr.io/vizvasanlya/unikctl/nginx:latest

			Attach the unikernel to an existing network kraft0:
			$ unikctl run --network kraft0

			Run a Linux userspace binary in POSIX-/binary-compatibility mode:
			$ unikctl run a.out

			Supply an initramfs CPIO archive file to the unikernel for its rootfs:
			$ unikctl run --rootfs ./initramfs.cpio

			Supply a path which is dynamically serialized into an initramfs CPIO archive:
			$ unikctl run --rootfs ./path/to/rootfs

			Mount a bi-directional path from on the host to the unikernel mapped to /dir:
			$ unikctl run -v ./path/to/dir:/dir

			Supply a read-only root file system at / via initramfs CPIO archive and mount a bi-directional volume at /dir:
			$ unikctl run --rootfs ./initramfs.cpio --volume ./path/to/dir:/dir

			Customize the default content directory of the official Unikraft NGINX OCI-compatible unikernel and map port 8080 to localhost:
			$ unikctl run -v ./path/to/html:/nginx/html -p 8080:80 ghcr.io/vizvasanlya/unikctl/nginx:latest
		`),
		Annotations: map[string]string{
			cmdfactory.AnnotationHelpGroup: "run",
		},
	})
	if err != nil {
		panic(err)
	}

	cmd.Flags().Var(
		cmdfactory.NewEnumFlag[mplatform.Platform](
			mplatform.Platforms(),
			mplatform.Platform("auto"),
		),
		"plat",
		"Set the platform virtual machine monitor driver.",
	)

	cmd.Flags().Var(
		cmdfactory.NewEnumFlag[initrd.FsType](
			initrd.FsTypes(),
			initrd.FsTypeCpio,
		),
		"rootfs-type",
		"Set the type of the format of the rootfs (cpio/erofs)",
	)

	return cmd
}

func (opts *RunOptions) Pre(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	if cmd != nil && cmd.Name() == "deploy" {
		// Deploy is the async UX surface and should never block on log streaming.
		opts.Detach = true
	}

	if opts.Debug {
		opts.WithKernelDbg = true
	}

	if normalized := runtimeutil.Normalize(opts.Runtime, "latest"); normalized != "" {
		opts.Runtime = normalized
	}

	opts.platform = mplatform.PlatformUnknown
	opts.Platform = cmd.Flag("plat").Value.String()
	opts.hostPlatform = mplatform.PlatformUnknown
	opts.hostMode = mplatform.SystemUnknown
	if cmd.Flag("rootfs-type").Changed && cmd.Flag("rootfs-type").Value.String() != "" {
		opts.RootfsType = initrd.FsType(cmd.Flag("rootfs-type").Value.String())
	}

	if opts.RunAs == "" || !set.NewStringSet("kernel", "project").Contains(opts.RunAs) {
		// Set use of the global package manager.
		ctx, err := packmanager.WithDefaultUmbrellaManagerInContext(cmd.Context())
		if err != nil {
			return err
		}

		cmd.SetContext(ctx)
	}

	if opts.RunAs != "" {
		runners, err := runnersByName()
		if err != nil {
			return err
		}
		if _, ok := runners[opts.RunAs]; !ok {
			choices := make([]string, len(runners))
			i := 0

			for choice := range runners {
				choices[i] = choice
				i++
			}

			return fmt.Errorf("unknown runner: %s (choice of %v)", opts.RunAs, choices)
		}
	}

	if opts.InitRd != "" {
		log.G(ctx).Warn("the --initrd flag is deprecated in favour of --rootfs")

		if opts.Rootfs != "" {
			log.G(ctx).Warn("both --initrd and --rootfs are set! ignorning value of --initrd")
		} else {
			log.G(ctx).Warn("for backwards-compatibility reasons the value of --initrd is set to --rootfs")
			opts.Rootfs = opts.InitRd
		}
	}

	if opts.Rootfs != "" && !filepath.IsAbs(opts.Rootfs) {
		abs, err := filepath.Abs(opts.Rootfs)
		if err != nil {
			return fmt.Errorf("getting absolute path of rootfs: %w", err)
		}
		opts.Rootfs = abs
	}

	if isDockerfileRootfs(opts.Rootfs) {
		return fmt.Errorf("dockerfile-based rootfs is disabled: use source build pipeline")
	}

	if opts.Memory != "" {
		qty, err := resource.ParseQuantity(opts.Memory)
		if err != nil {
			return fmt.Errorf("could not parse memory quantity: %w", err)
		}

		if qty.Value() < 1024*1024 {
			return fmt.Errorf("memory must be at least 1Mi")
		}
	}

	return nil
}

func (opts *RunOptions) detectAndSetHostPlatform(ctx context.Context) error {
	var err error

	if opts.hostPlatform == mplatform.PlatformUnknown || opts.hostMode == mplatform.SystemUnknown {
		opts.hostPlatform, opts.hostMode, err = mplatform.Detect(ctx)
		if err != nil {
			if opts.Platform != "" && opts.Platform != "auto" {
				log.G(ctx).WithError(err).WithField("platform", opts.Platform).Warn("host platform auto-detection failed; using requested platform")
				opts.hostPlatform = mplatform.PlatformUnknown
				opts.hostMode = mplatform.SystemUnknown
			} else {
				return err
			}
		}
	}

	if opts.Platform == "" || opts.Platform == "auto" {
		if opts.hostPlatform == mplatform.PlatformUnknown {
			return fmt.Errorf("could not detect host platform and no explicit platform was provided")
		}
		opts.platform = opts.hostPlatform
		opts.Platform = opts.hostPlatform.String()
	} else {
		var ok bool
		opts.platform, ok = mplatform.PlatformsByName()[opts.Platform]
		if !ok {
			return fmt.Errorf("unknown platform driver '%s', however your system supports '%s'", opts.Platform, opts.hostPlatform.String())
		}
	}
	if opts.hostPlatform != mplatform.PlatformUnknown && opts.hostPlatform.String() == opts.Platform && opts.hostMode == mplatform.SystemGuest && !opts.DisableAccel {
		log.G(ctx).Warn("using hardware emulation")
		opts.DisableAccel = true
	}

	machineStrategy, ok := mplatform.Strategies()[opts.platform]
	if !ok {
		return fmt.Errorf("unsupported platform driver: %s (contributions welcome!)", opts.Platform)
	}

	opts.machineController, err = machineStrategy.NewMachineV1alpha1(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (opts *RunOptions) detectAndSetHostArchitecture(ctx context.Context) error {
	var err error

	if opts.Architecture == "" || opts.Architecture == "auto" {
		opts.Architecture, err = ukarch.HostArchitecture()
		if err != nil {
			return fmt.Errorf("could not get host architecture: %w", err)
		}
	}

	if _, found := ukarch.ArchitecturesByName()[opts.Architecture]; !found {
		log.G(ctx).WithFields(logrus.Fields{
			"arch": opts.Architecture,
		}).Warn("unknown or incompatible")
	}

	return nil
}

func (opts *RunOptions) Run(ctx context.Context, args []string) (retErr error) {
	if controlplaneapi.Enabled(ctx) {
		return opts.remoteDeploy(ctx, args)
	}

	var err error

	machine := &machineapi.Machine{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: machineapi.MachineSpec{
			Platform: opts.platform.String(),
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
			},
		},
	}

	var opStore *operations.Store
	var opRecord *operations.Record
	if !controlplaneapi.InServerMode(ctx) {
		var opErr error
		opStore, opRecord, opErr = startDeployOperation(ctx, args)
		if opErr != nil {
			log.G(ctx).WithError(opErr).Debug("could not initialize operation tracking")
		}
		if opStore != nil && opRecord != nil {
			fmt.Fprintf(iostreams.G(ctx).ErrOut, "operation: %s\n", opRecord.ID)
			if err := opStore.SetState(opRecord.ID, operations.StateRunning, "resolving deployment input"); err != nil {
				log.G(ctx).WithError(err).Debug("could not update deploy operation state")
			}
		}
	}

	deployedMachineName := ""
	completionMessage := "deployment completed"
	markSubmitted := opts.Detach

	defer func() {
		if opStore == nil || opRecord == nil {
			return
		}

		if retErr != nil {
			if err := opStore.Fail(opRecord.ID, retErr); err != nil {
				log.G(ctx).WithError(err).Debug("could not mark deploy operation as failed")
			}
			return
		}

		if markSubmitted {
			msg := completionMessage
			if deployedMachineName != "" {
				msg = fmt.Sprintf("deployment submitted for %s", deployedMachineName)
			}
			if err := opStore.SetState(opRecord.ID, operations.StateSubmitted, msg); err != nil {
				log.G(ctx).WithError(err).Debug("could not mark deploy operation as submitted")
			}
			return
		}

		if err := opStore.SetState(opRecord.ID, operations.StateSucceeded, completionMessage); err != nil {
			log.G(ctx).WithError(err).Debug("could not mark deploy operation as succeeded")
		}
	}()

	args, err = opts.prepareSourceDirectory(ctx, args)
	if err != nil {
		return err
	}

	var run runner
	var errs []error
	runners, err := runners()
	if err != nil {
		return err
	}

	// Iterate through the list of built-in runners which sequentially tests and
	// first test whether the --as flag has been set to force a specific runner or
	// whether the current context matches the requirements for being run given
	// its context.  If prompting is enabled and multiple candidates are
	// discovered, the user is provided the choice as to which runner to use;
	// otherwise the determined runner will be used automatically.

	log.G(ctx).Debug("determining how to proceed given provided input and context")

	var candidates []runner

	for _, candidate := range runners {
		if opts.RunAs != "" && candidate.Name() != opts.RunAs {
			continue
		}

		log.G(ctx).
			WithField("runner", candidate.Name()).
			Trace("checking runnability")

		capable, err := candidate.Runnable(ctx, opts, args...)
		if capable && err == nil {
			candidates = append(candidates, candidate)
		} else if err != nil {
			errs = append(errs, err)
			log.G(ctx).
				WithField("candidate", candidate.Name()).
				Tracef("candidate is not runnable because: %v", err)
		}
	}

	if len(candidates) == 0 {
		return fmt.Errorf("could not determine how to run provided input: %w", errors.Join(errs...))
	} else if len(candidates) == 1 {
		run = candidates[0]
	} else if !config.G[config.KraftKit](ctx).NoPrompt {
		candidate, err := selection.Select[runner]("multiple runnable contexts discovered: how would you like to proceed?", candidates...)
		if err != nil {
			return err
		}

		run = *candidate

		log.G(ctx).Infof("use --as=%s to skip this prompt in the future", run.Name())
	} else {
		return fmt.Errorf("multiple contexts discovered: %v", candidates)
	}

	log.G(ctx).WithField("candidate", run.Name()).Debug("using compatible context")

	// Prepare the machine specification based on the compatible runner.
	if err := run.Prepare(ctx, opts, machine, args...); err != nil {
		return err
	}

	if isDockerfileRootfs(opts.Rootfs) {
		return fmt.Errorf("dockerfile-based rootfs is disabled: use source build pipeline")
	}

	// Assign ports by checking for conflicts with existing machines.
	if err := opts.assignPorts(ctx, machine); err != nil {
		return err
	}

	// Set whether to disable acceleration of the CPU.
	machine.Spec.Emulation = opts.DisableAccel

	// Override with command-line flags
	if len(opts.KernelArgs) > 0 {
		machine.Spec.KernelArgs = opts.KernelArgs
	}

	if len(opts.Memory) > 0 {
		quantity, err := resource.ParseQuantity(opts.Memory)
		if err != nil {
			return err
		}

		machine.Spec.Resources.Requests[corev1.ResourceMemory] = quantity
	}

	if err := opts.parseNetworks(ctx, machine); err != nil {
		return err
	}

	if err := opts.assignName(ctx, machine); err != nil {
		return err
	}
	deployedMachineName = machine.ObjectMeta.Name
	if opStore != nil && opRecord != nil {
		if err := opStore.SetMachine(opRecord.ID, deployedMachineName); err != nil {
			log.G(ctx).WithError(err).Debug("could not attach machine to deploy operation")
		}
	}

	if err := opts.parseVolumes(ctx, machine); err != nil {
		return err
	}

	if err := opts.prepareRootfs(ctx, machine); err != nil {
		return err
	}

	if err := opts.parseEnvs(ctx, machine); err != nil {
		return err
	}

	// Create the machine
	machine, err = opts.machineController.Create(ctx, machine)
	if err != nil {
		return err
	}
	deployedMachineName = machine.Name
	if opStore != nil && opRecord != nil {
		if err := opStore.SetMachine(opRecord.ID, deployedMachineName); err != nil {
			log.G(ctx).WithError(err).Debug("could not attach created machine to deploy operation")
		}
	}

	if opts.NoStart {
		markSubmitted = false
		completionMessage = fmt.Sprintf("machine %s created", machine.Name)

		// Output the name of the instance such that it can be piped
		fmt.Fprintf(iostreams.G(ctx).Out, "%s\n", machine.Name)
		return nil
	}

	completionMessage = fmt.Sprintf("machine %s started", machine.Name)

	if err := start.Start(ctx, &start.StartOptions{
		Detach:   opts.Detach,
		Platform: opts.platform.String(),
		Remove:   opts.Remove,
	}, machine.Name); err != nil {
		return err
	}

	opts.persistLocalDeployment(ctx, machine, args)

	if opts.Detach && !controlplaneapi.InServerMode(ctx) {
		if launchURL := launchURLFromMachinePorts(machine.Spec.Ports, "127.0.0.1"); launchURL != "" {
			fmt.Fprintf(iostreams.G(ctx).Out, "launch: %s\n", launchURL)
		}
	}

	return nil
}

func (opts *RunOptions) prepareSourceDirectory(ctx context.Context, args []string) ([]string, error) {
	deployArgs := append([]string{}, args...)
	if len(deployArgs) == 0 {
		deployArgs = []string{"."}
	}

	first := strings.TrimSpace(deployArgs[0])
	if first == "" {
		return args, nil
	}

	stat, err := os.Stat(first)
	if err != nil || !stat.IsDir() {
		return args, nil
	}

	buildPlatform := opts.Platform
	if buildPlatform == "auto" {
		buildPlatform = ""
	}

	buildArch := opts.Architecture
	if buildArch == "auto" {
		buildArch = ""
	}

	buildOpts := &buildcmd.BuildOptions{
		Architecture: buildArch,
		Debug:        opts.Debug || opts.WithKernelDbg,
		Kraftfile:    opts.Kraftfile,
		Platform:     buildPlatform,
		Rootfs:       opts.Rootfs,
		RootfsType:   opts.RootfsType,
		TargetName:   opts.Target,
		Workdir:      first,
	}

	if err := buildcmd.Build(ctx, buildOpts, first); err != nil {
		return nil, err
	}

	if opts.Kraftfile == "" && strings.TrimSpace(buildOpts.Kraftfile) != "" {
		opts.Kraftfile = buildOpts.Kraftfile
	}

	if opts.Rootfs == "" && strings.TrimSpace(buildOpts.Rootfs) != "" {
		opts.Rootfs = buildOpts.Rootfs
	}

	if opts.RootfsType == "" {
		if buildOpts.RootfsType != "" {
			opts.RootfsType = buildOpts.RootfsType
		} else if opts.Rootfs != "" {
			opts.RootfsType = initrd.FsTypeCpio
		}
	}

	if len(args) == 0 {
		return deployArgs, nil
	}

	return deployArgs, nil
}

func isDockerfileRootfs(path string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(path)), "dockerfile")
}

func startDeployOperation(ctx context.Context, args []string) (*operations.Store, *operations.Record, error) {
	store, err := operations.NewStore(ctx)
	if err != nil {
		return nil, nil, err
	}

	record, err := store.Start(operations.KindDeploy, args, "deployment queued")
	if err != nil {
		return nil, nil, err
	}

	return store, record, nil
}

func (opts *RunOptions) remoteDeploy(ctx context.Context, args []string) error {
	client, err := controlplaneapi.NewClientFromContext(ctx)
	if err != nil {
		return err
	}

	projectDeploy, err := loadProjectDeployConfig(args)
	if err != nil {
		return err
	}

	traceID := newRequestTraceID()
	idempotencyKey := deployIdempotencyKey(opts, args, projectDeploy)

	deployArgs, sourceArtifactID, sourceArtifactPath, rootfsArtifactID, rootfsArtifactPath, err := prepareRemoteDeployInput(ctx, client, args, opts.Rootfs)
	if err != nil {
		return err
	}

	response, err := client.Deploy(ctx, controlplaneapi.DeployRequest{
		Args:               deployArgs,
		Debug:              opts.Debug || opts.WithKernelDbg,
		Memory:             opts.Memory,
		Name:               opts.Name,
		Rootfs:             opts.Rootfs,
		Runtime:            opts.Runtime,
		Target:             opts.Target,
		Platform:           opts.Platform,
		Architecture:       opts.Architecture,
		ArtifactID:         sourceArtifactID,
		ArtifactPath:       sourceArtifactPath,
		RootfsArtifactID:   rootfsArtifactID,
		RootfsArtifactPath: rootfsArtifactPath,
		ServiceName:        strings.TrimSpace(projectDeploy.Deploy.ServiceName),
		Replicas:           projectDeploy.Deploy.Replicas,
		Strategy:           strings.TrimSpace(projectDeploy.Deploy.Strategy),
		MaxUnavailable:     projectDeploy.Deploy.MaxUnavailable,
		MaxSurge:           projectDeploy.Deploy.MaxSurge,
		CanaryPercent:      projectDeploy.Deploy.CanaryPercent,
		HealthCheck: struct {
			Path            string `json:"path,omitempty"`
			Port            int    `json:"port,omitempty"`
			IntervalSeconds int    `json:"interval_seconds,omitempty"`
			TimeoutSeconds  int    `json:"timeout_seconds,omitempty"`
		}{
			Path:            strings.TrimSpace(projectDeploy.Deploy.HealthCheck.Path),
			Port:            projectDeploy.Deploy.HealthCheck.Port,
			IntervalSeconds: projectDeploy.Deploy.HealthCheck.IntervalSeconds,
			TimeoutSeconds:  projectDeploy.Deploy.HealthCheck.TimeoutSeconds,
		},
		IdempotencyKey: idempotencyKey,
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

func prepareRemoteDeployInput(
	ctx context.Context,
	client *controlplaneapi.Client,
	args []string,
	rootfs string,
) ([]string, string, string, string, string, error) {
	deployArgs := append([]string{}, args...)
	if len(deployArgs) == 0 {
		deployArgs = []string{"."}
	}
	sourceArtifactID := ""
	sourceArtifactPath := ""
	rootfsArtifactID := ""
	rootfsArtifactPath := ""

	if len(deployArgs) > 0 {
		sourcePath := strings.TrimSpace(deployArgs[0])
		if sourcePath != "" {
			artifactID, artifactPath, err := uploadArtifactIfLocalPath(ctx, client, sourcePath, "source")
			if err != nil {
				return nil, "", "", "", "", err
			}
			sourceArtifactID = artifactID
			sourceArtifactPath = artifactPath
		}
	}

	if strings.TrimSpace(rootfs) != "" {
		artifactID, artifactPath, err := uploadArtifactIfLocalPath(ctx, client, rootfs, "rootfs")
		if err != nil {
			return nil, "", "", "", "", err
		}
		rootfsArtifactID = artifactID
		rootfsArtifactPath = artifactPath
	}

	return deployArgs, sourceArtifactID, sourceArtifactPath, rootfsArtifactID, rootfsArtifactPath, nil
}

func uploadArtifactIfLocalPath(ctx context.Context, client *controlplaneapi.Client, path string, label string) (string, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", nil
	}

	info, err := os.Stat(path)
	if err != nil {
		// Not a local path on this client; keep server-side interpretation.
		return "", "", nil
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s path: %w", label, err)
	}

	artifactPath := "."
	if !info.IsDir() {
		artifactPath = filepath.Base(absolutePath)
	}

	fmt.Fprintf(iostreams.G(ctx).ErrOut, "uploading %s artifact to control plane...\n", label)
	artifactID, err := client.UploadSource(ctx, absolutePath)
	if err != nil {
		return "", "", err
	}

	return artifactID, artifactPath, nil
}

func newRequestTraceID() string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("trace-%d", os.Getpid())
	}
	return fmt.Sprintf("trace-%x", random)
}

func deployIdempotencyKey(opts *RunOptions, args []string, projectDeploy deployProjectConfig) string {
	parts := []string{
		strings.Join(args, "\x00"),
		strings.TrimSpace(opts.Name),
		strings.TrimSpace(opts.Rootfs),
		strings.TrimSpace(opts.Runtime),
		strings.TrimSpace(opts.Target),
		strings.TrimSpace(opts.Platform),
		strings.TrimSpace(opts.Architecture),
		strings.TrimSpace(opts.Memory),
		fmt.Sprintf("%t", opts.Debug || opts.WithKernelDbg),
		strings.TrimSpace(projectDeploy.Deploy.ServiceName),
		fmt.Sprintf("%d", projectDeploy.Deploy.Replicas),
		strings.TrimSpace(projectDeploy.Deploy.Strategy),
		fmt.Sprintf("%d", projectDeploy.Deploy.MaxUnavailable),
		fmt.Sprintf("%d", projectDeploy.Deploy.MaxSurge),
		fmt.Sprintf("%d", projectDeploy.Deploy.CanaryPercent),
		strings.TrimSpace(projectDeploy.Deploy.HealthCheck.Path),
		fmt.Sprintf("%d", projectDeploy.Deploy.HealthCheck.Port),
		fmt.Sprintf("%d", projectDeploy.Deploy.HealthCheck.IntervalSeconds),
		fmt.Sprintf("%d", projectDeploy.Deploy.HealthCheck.TimeoutSeconds),
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "deploy-" + hex.EncodeToString(sum[:12])
}

func loadProjectDeployConfig(args []string) (deployProjectConfig, error) {
	cfg := deployProjectConfig{}

	source := "."
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		source = strings.TrimSpace(args[0])
	}

	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return cfg, nil
	}

	path := filepath.Join(source, "unik.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}

	return cfg, nil
}
