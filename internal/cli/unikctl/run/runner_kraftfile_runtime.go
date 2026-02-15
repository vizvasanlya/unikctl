// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package run

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/klauspost/cpuid/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	volumeapi "unikctl.sh/api/volume/v1alpha1"
	"unikctl.sh/config"
	"unikctl.sh/internal/runtimeutil"
	"unikctl.sh/log"
	"unikctl.sh/pack"
	"unikctl.sh/packmanager"
	"unikctl.sh/tui/paraprogress"
	"unikctl.sh/tui/processtree"
	"unikctl.sh/tui/selection"
	"unikctl.sh/unikraft/app"
	"unikctl.sh/unikraft/export/v0/ukrandom"
	"unikctl.sh/unikraft/target"
)

type runnerKraftfileRuntime struct {
	args    []string
	project app.Application
}

// String implements Runner.
func (runner *runnerKraftfileRuntime) String() string {
	return fmt.Sprintf("run the cwd's Kraftfile and use '%s' as arg(s)", strings.Join(runner.args, " "))
}

// Name implements Runner.
func (runner *runnerKraftfileRuntime) Name() string {
	return "kraftfile-runtime"
}

// Runnable implements Runner.
func (runner *runnerKraftfileRuntime) Runnable(ctx context.Context, opts *RunOptions, args ...string) (bool, error) {
	var err error

	cwd, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("getting current working directory: %w", err)
	}

	if len(args) == 0 {
		opts.workdir = cwd
	} else {
		opts.workdir = cwd
		runner.args = args
		if f, err := os.Stat(args[0]); err == nil && f.IsDir() {
			opts.workdir = args[0]
			runner.args = args[1:]
		}
	}

	popts := []app.ProjectOption{
		app.WithProjectWorkdir(opts.workdir),
	}

	if len(opts.Kraftfile) > 0 {
		popts = append(popts, app.WithProjectKraftfile(opts.Kraftfile))
	} else {
		popts = append(popts, app.WithProjectDefaultKraftfiles())
	}

	runner.project, err = app.NewProjectFromOptions(ctx, popts...)
	if err != nil {
		return false, fmt.Errorf("could not instantiate project directory %s: %v", opts.workdir, err)
	}

	if runner.project.Runtime() == nil && len(opts.Runtime) == 0 {
		return false, fmt.Errorf("cannot run project without runtime directive")
	}

	if runner.project != nil && runner.project.Rootfs() != "" && opts.Rootfs == "" {
		opts.Rootfs = runner.project.Rootfs()
	}

	if runner.project != nil && runner.project.InitrdFsType().String() != "" && opts.RootfsType == "" {
		opts.RootfsType = runner.project.InitrdFsType()
	}

	return true, nil
}

// Prepare implements Runner.
func (runner *runnerKraftfileRuntime) Prepare(ctx context.Context, opts *RunOptions, machine *machineapi.Machine, args ...string) error {
	var err error
	var targ target.Target

	targets := runner.project.Targets()
	var qopts []packmanager.QueryOption
	var runtimeName string
	var runtimeCandidates []runtimeutil.Reference
	if len(opts.Runtime) > 0 {
		runtimeName = strings.TrimSpace(opts.Runtime)
		runtimeCandidates = runtimeutil.Candidates(runtimeName, "latest")
		if len(runtimeCandidates) == 0 {
			return fmt.Errorf("invalid runtime value: %s", opts.Runtime)
		}
	} else {
		runtimeName = fmt.Sprintf("%s:%s", runner.project.Runtime().Name(), runner.project.Runtime().Version())
		runtimeCandidates = runtimeutil.Candidates(runtimeName, "latest")
		if len(runtimeCandidates) == 0 {
			return fmt.Errorf("invalid runtime value: %s", runtimeName)
		}
	}

	if len(targets) == 1 {
		targ = targets[0]
	} else if len(targets) > 1 {
		// Filter project targets by any provided CLI options
		targets = target.Filter(
			targets,
			"",
			"",
			opts.Target,
		)

		switch {
		case len(targets) == 0:
			return fmt.Errorf("could not detect any project targets based on %s/%s", opts.platform.String(), opts.Architecture)

		case len(targets) == 1:
			targ = targets[0]

		case config.G[config.KraftKit](ctx).NoPrompt && len(targets) > 1:
			return fmt.Errorf("could not determine what to run based on provided CLI arguments")

		default:
			archFilter := opts.Architecture
			if archFilter == "auto" {
				archFilter = ""
			}
			platformFilter := opts.Platform
			if platformFilter == "auto" {
				platformFilter = ""
			}

			targets = target.Filter(
				targets,
				archFilter,
				platformFilter,
				opts.Target,
			)

			switch {
			case len(targets) == 0:
				return fmt.Errorf("could not detect any built project targets based on %s/%s", platformFilter, archFilter)

			case len(targets) == 1:
				targ = targets[0]

			default:
				targ = selectPreferredTarget(targets)
			}
		}
	}

	if targ != nil {
		opts.Platform = targ.Platform().String()
		if err := opts.detectAndSetHostPlatform(ctx); err != nil {
			return fmt.Errorf("could not detect platform: %w", err)
		}

		opts.Architecture = targ.Architecture().String()
		if err := opts.detectAndSetHostArchitecture(ctx); err != nil {
			return fmt.Errorf("could not detect architecture: %w", err)
		}

		var kconfigs []string
		for _, kc := range targ.KConfig() {
			kconfigs = append(kconfigs, kc.String())
		}

		qopts = append(qopts,
			packmanager.WithPlatform(opts.Platform),
			packmanager.WithArchitecture(opts.Architecture),
			packmanager.WithKConfig(kconfigs),
		)
	}

	var packs []pack.Package
	var resolvedRuntime runtimeutil.Reference

	treemodel, err := processtree.NewProcessTree(
		ctx,
		[]processtree.ProcessTreeOption{
			processtree.IsParallel(false),
			processtree.WithRenderer(
				log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) != log.FANCY,
			),
			processtree.WithFailFast(true),
			processtree.WithHideOnSuccess(true),
		},
		processtree.NewProcessTreeItem(
			fmt.Sprintf("searching for %s", runtimeName),
			"",
			func(ctx context.Context) error {
				packs, resolvedRuntime, err = queryRuntimePackageCandidates(ctx, runtimeCandidates, qopts)
				if err != nil {
					return err
				}

				return nil
			},
		),
	)
	if err != nil {
		return err
	}

	if err := treemodel.Start(); err != nil {
		return err
	}
	if len(packs) == 0 {
		hint := runtimeutil.MissingRuntimeHint(runtimeName)
		if hint == "" {
			return fmt.Errorf("could not find runtime %s; tried: %s", runtimeName, joinRuntimeLookupCandidates(runtimeCandidates))
		}
		return fmt.Errorf("could not find runtime %s; tried: %s (%s)", runtimeName, joinRuntimeLookupCandidates(runtimeCandidates), hint)
	}

	var found pack.Package

	if len(packs) == 1 {
		found = packs[0]
	} else {
		platformFilter := opts.Platform
		if platformFilter == "auto" {
			platformFilter = ""
		}
		archFilter := opts.Architecture
		if archFilter == "auto" {
			archFilter = ""
		}

		compatible := []pack.Package{}

		for _, p := range packs {
			pt := p.(target.Target)
			if archFilter != "" && pt.Architecture().String() != archFilter {
				continue
			}
			if platformFilter != "" && pt.Platform().String() != platformFilter {
				continue
			}
			if archFilter == "" && platformFilter == "" && !isPreferredRuntimePlatform(pt.Platform().String()) {
				continue
			}
			compatible = append(compatible, p)
		}

		if len(compatible) == 0 && archFilter == "" && platformFilter == "" {
			// If no preferred platform is available, keep all candidates.
			compatible = packs
		}

		// Could not find a package that matches the desired architecture and
		// platform, prompt with previous available set of packages.
		if len(compatible) == 0 {
			if !config.G[config.KraftKit](ctx).NoPrompt {
				log.G(ctx).Warnf("could not find package '%s' based on %s/%s", runtimeName, platformFilter, archFilter)
				p, err := selection.Select("select alternative package with same name to continue", packs...)
				if err != nil {
					return fmt.Errorf("could not select package: %w", err)
				}

				found = *p
			} else {
				return fmt.Errorf("could not find package '%s' based on %s/%s but %d others found but prompting has been disabled", runtimeName, platformFilter, archFilter, len(packs))
			}
		} else if len(compatible) == 1 { // An exact match was found!
			found = compatible[0]
		} else { // More than 1 match found, pick a deterministic preferred package.
			found = selectPreferredPackage(compatible)
			log.G(ctx).WithFields(map[string]interface{}{
				"runtime":    formatRuntimeLookupCandidate(resolvedRuntime),
				"platform":   found.(target.Target).Platform().String(),
				"arch":       found.(target.Target).Architecture().String(),
				"candidates": len(compatible),
			}).Info("multiple runtime packages available; selecting preferred candidate")
		}
	}

	if runner.project.Rootfs() != "" && opts.Rootfs == "" {
		opts.Rootfs = runner.project.Rootfs()
	}

	// Create a temporary directory where the image can be stored
	tempDir, err := os.MkdirTemp("", "kraft-run-")
	if err != nil {
		return err
	}

	if exists, _, err := found.PulledAt(ctx); !exists || err != nil {
		paramodel, err := paraprogress.NewParaProgress(
			ctx,
			[]*paraprogress.Process{paraprogress.NewProcess(
				fmt.Sprintf("pulling %s", found.String()),
				func(ctx context.Context, w func(progress float64)) error {
					popts := []pack.PullOption{}
					if log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) == log.FANCY {
						popts = append(popts, pack.WithPullProgressFunc(w))
					}

					return found.Pull(
						ctx,
						popts...,
					)
				},
			)},
			paraprogress.IsParallel(false),
			paraprogress.WithRenderer(
				log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) != log.FANCY,
			),
			paraprogress.WithFailFast(true),
		)
		if err != nil {
			return err
		}

		if err := paramodel.Start(); err != nil {
			return err
		}
	}

	if err := found.Unpack(
		ctx,
		tempDir,
	); err != nil {
		return fmt.Errorf("unpacking the image: %w", err)
	}

	// Crucially, the catalog should return an interface that also implements
	// target.Target.  This demonstrates that the implementing package can
	// resolve application kernels.
	runtime, ok := found.(target.Target)
	if !ok {
		return fmt.Errorf("package does not convert to target")
	}

	opts.Platform = runtime.Platform().String()
	if err := opts.detectAndSetHostPlatform(ctx); err != nil {
		return fmt.Errorf("could not detect platform: %w", err)
	}

	opts.Architecture = runtime.Architecture().String()
	if err := opts.detectAndSetHostArchitecture(ctx); err != nil {
		return fmt.Errorf("could not detect architecture: %w", err)
	}

	log.G(ctx).
		WithField("arch", opts.Architecture).
		WithField("plat", opts.Platform).
		Info("using")

	machine.Spec.Architecture = runtime.Architecture().Name()
	machine.Spec.Platform = runtime.Platform().Name()
	machine.Spec.Kernel = fmt.Sprintf("%s://%s:%s", packs[0].Format(), runtime.Name(), runtime.Version())

	// Use the symbolic debuggable kernel image?
	if opts.WithKernelDbg {
		machine.Status.KernelPath = runtime.KernelDbg()
	} else {
		machine.Status.KernelPath = runtime.Kernel()
	}

	if opts.Rootfs == "" {
		if runner.project.Rootfs() != "" {
			opts.Rootfs = runner.project.Rootfs()
		} else if runtime.Initrd() != nil {
			machine.Status.InitrdPath, err = runtime.Initrd().Build(ctx)
			if err != nil {
				return err
			}

			for _, entry := range runtime.Initrd().Env() {
				k, v, ok := strings.Cut(entry, "=")
				if !ok {
					continue
				}

				machine.Spec.Env[k] = v
			}

			machine.Spec.ApplicationArgs = runtime.Initrd().Args()
		}
	}

	if len(runner.args) > 0 {
		machine.Spec.ApplicationArgs = runner.args
	} else if len(runner.project.Command()) > 0 {
		machine.Spec.ApplicationArgs = runner.project.Command()
	} else if len(runtime.Command()) > 0 {
		machine.Spec.ApplicationArgs = runtime.Command()
	}

	var kernelArgs []string
	hasUkRandom := !runtime.KConfig().AllNoOrUnset(
		"CONFIG_LIBUKRANDOM",
	)
	hasCmdlineSupport := !runtime.KConfig().AllNoOrUnset(
		"CONFIG_LIBUKRANDOM_CMDLINE_SEED",
	)
	hasNoCpuRandomnessSupport := runtime.KConfig().AllNoOrUnset("CONFIG_LIBUKRANDOM_LCPU") ||
		!(cpuid.CPU.Has(cpuid.RDRAND) || cpuid.CPU.Has(cpuid.RNDR))
	if hasUkRandom && hasNoCpuRandomnessSupport && hasCmdlineSupport {
		kernelArgs = append(kernelArgs, ukrandom.ParamRandomSeed.WithValue(ukrandom.NewRandomSeed()).String())
	} else if hasUkRandom && hasNoCpuRandomnessSupport && !hasCmdlineSupport {
		log.G(ctx).Warn("RDRAND is not supported by the host CPU to be able to run Unikraft v0.17.0 and greater with CPU-generated randomness")
	}

	machine.Spec.KernelArgs = kernelArgs

	// If automounting is enabled, and an initramfs is provided, set it as a
	// volume if a initram has been provided.
	if runtime.KConfig().AnyYes(
		"CONFIG_LIBVFSCORE_FSTAB", // Deprecated
		"CONFIG_LIBVFSCORE_AUTOMOUNT_UP",
	) && (len(machine.Status.InitrdPath) > 0 || len(opts.Rootfs) > 0) {
		machine.Spec.Volumes = append(machine.Spec.Volumes, volumeapi.Volume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rootfs",
			},
			Spec: volumeapi.VolumeSpec{
				Driver:      "initrd",
				Destination: "/",
			},
		})
	}

	if err := opts.parseKraftfileVolumes(ctx, runner.project, machine); err != nil {
		return err
	}

	if err := opts.parseKraftfileEnv(ctx, runner.project, machine); err != nil {
		return err
	}

	return nil
}

func isPreferredRuntimePlatform(platform string) bool {
	switch platform {
	case "qemu", "firecracker", "fc", "xen":
		return true
	default:
		return false
	}
}

func selectPreferredPackage(packs []pack.Package) pack.Package {
	if len(packs) == 0 {
		return nil
	}

	platformRank := map[string]int{
		"qemu":        0,
		"firecracker": 1,
		"fc":          1,
		"xen":         2,
	}

	sort.SliceStable(packs, func(i, j int) bool {
		pi := packs[i].(target.Target).Platform().String()
		pj := packs[j].(target.Target).Platform().String()

		ri, ok := platformRank[pi]
		if !ok {
			ri = 100
		}
		rj, ok := platformRank[pj]
		if !ok {
			rj = 100
		}

		if ri != rj {
			return ri < rj
		}

		if packs[i].(target.Target).Architecture().String() != packs[j].(target.Target).Architecture().String() {
			return packs[i].(target.Target).Architecture().String() < packs[j].(target.Target).Architecture().String()
		}

		if packs[i].Name() != packs[j].Name() {
			return packs[i].Name() < packs[j].Name()
		}

		return packs[i].Version() < packs[j].Version()
	})

	return packs[0]
}

func selectPreferredTarget(targets []target.Target) target.Target {
	if len(targets) == 0 {
		return nil
	}

	platformRank := map[string]int{
		"qemu":        0,
		"firecracker": 1,
		"fc":          1,
		"xen":         2,
	}

	sort.SliceStable(targets, func(i, j int) bool {
		pi := targets[i].Platform().String()
		pj := targets[j].Platform().String()

		ri, ok := platformRank[pi]
		if !ok {
			ri = 100
		}
		rj, ok := platformRank[pj]
		if !ok {
			rj = 100
		}

		if ri != rj {
			return ri < rj
		}

		if targets[i].Architecture().String() != targets[j].Architecture().String() {
			return targets[i].Architecture().String() < targets[j].Architecture().String()
		}

		return targets[i].Name() < targets[j].Name()
	})

	return targets[0]
}

func queryRuntimePackageCandidates(
	ctx context.Context,
	candidates []runtimeutil.Reference,
	base []packmanager.QueryOption,
) ([]pack.Package, runtimeutil.Reference, error) {
	var queryErr error
	for _, candidate := range candidates {
		options := append([]packmanager.QueryOption{}, base...)
		queryName := candidate.Name
		if candidate.Digest != "" {
			queryName = fmt.Sprintf("%s@%s", candidate.Name, candidate.Digest)
		}
		options = append(options, packmanager.WithName(queryName))
		if candidate.Digest == "" && candidate.Version != "" {
			options = append(options, packmanager.WithVersion(candidate.Version))
		}

		packs, err := packmanager.G(ctx).Catalog(ctx, append(options, packmanager.WithRemote(false))...)
		if err != nil {
			queryErr = err
			continue
		}

		if len(packs) == 0 {
			packs, err = packmanager.G(ctx).Catalog(ctx, append(options, packmanager.WithRemote(true))...)
			if err != nil {
				queryErr = err
				continue
			}
		}

		if len(packs) > 0 {
			return packs, candidate, nil
		}
	}

	if queryErr != nil {
		return nil, runtimeutil.Reference{}, fmt.Errorf("could not query catalog: %w", queryErr)
	}

	return nil, runtimeutil.Reference{}, nil
}

func joinRuntimeLookupCandidates(candidates []runtimeutil.Reference) string {
	if len(candidates) == 0 {
		return "-"
	}
	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, formatRuntimeLookupCandidate(candidate))
	}
	return strings.Join(values, ", ")
}

func formatRuntimeLookupCandidate(candidate runtimeutil.Reference) string {
	value := candidate.String()
	if value == "" {
		return "-"
	}
	return value
}
