// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package build

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"unikctl.sh/config"
	"unikctl.sh/internal/cli/unikctl/utils"
	"unikctl.sh/internal/runtimeutil"
	"unikctl.sh/log"
	"unikctl.sh/pack"
	"unikctl.sh/packmanager"
	"unikctl.sh/tui/processtree"
	"unikctl.sh/unikraft/target"
)

type builderKraftfileRuntime struct{}

// String implements fmt.Stringer.
func (build *builderKraftfileRuntime) String() string {
	return "kraftfile-runtime"
}

// Buildable implements builder.
func (build *builderKraftfileRuntime) Buildable(ctx context.Context, opts *BuildOptions, args ...string) (bool, error) {
	if opts.NoRootfs {
		return false, fmt.Errorf("building rootfs disabled")
	}

	if opts.Project == nil {
		if err := opts.initProject(ctx); err != nil {
			return false, err
		}
	}

	if opts.Project.Runtime() == nil {
		return false, fmt.Errorf("cannot package without unikraft core specification")
	}

	if opts.Project.Rootfs() != "" && opts.Rootfs == "" {
		opts.Rootfs = opts.Project.Rootfs()
	}

	if opts.Project.InitrdFsType().String() != "" && opts.RootfsType == "" {
		opts.RootfsType = opts.Project.InitrdFsType()
	}

	return true, nil
}

func (*builderKraftfileRuntime) Prepare(ctx context.Context, opts *BuildOptions, _ ...string) error {
	var (
		selected *pack.Package
		packs    []pack.Package
		kconfigs []string
		resolved runtimeutil.Reference
		err      error
	)

	name := opts.Project.Runtime().Name()
	if opts.Platform == "kraftcloud" || (opts.Project.Runtime().Platform() != nil && opts.Project.Runtime().Platform().Name() == "kraftcloud") {
		name = utils.RewrapAsKraftCloudPackage(name)
	}
	version := opts.Project.Runtime().Version()
	candidates := runtimeutil.Candidates(composeRuntimeRef(name, version), "latest")

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
			fmt.Sprintf(
				"searching for %s:%s",
				name,
				version,
			),
			"",
			func(ctx context.Context) error {
				qopts := []packmanager.QueryOption{
					packmanager.WithArchitecture(opts.Architecture),
					packmanager.WithPlatform(opts.Platform),
					packmanager.WithKConfig(kconfigs),
				}

				packs, resolved, err = queryRuntimeCandidates(ctx, candidates, qopts)
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
		tried := joinRuntimeCandidates(candidates)
		if len(opts.Platform) > 0 && len(opts.Architecture) > 0 {
			return fmt.Errorf(
				"could not find runtime '%s' (%s/%s); tried: %s",
				opts.Project.Runtime().Name(),
				opts.Platform,
				opts.Architecture,
				tried,
			)
		} else if len(opts.Architecture) > 0 {
			return fmt.Errorf(
				"could not find runtime '%s' with '%s' architecture; tried: %s",
				opts.Project.Runtime().Name(),
				opts.Architecture,
				tried,
			)
		} else if len(opts.Platform) > 0 {
			return fmt.Errorf(
				"could not find runtime '%s' with '%s' platform; tried: %s",
				opts.Project.Runtime().Name(),
				opts.Platform,
				tried,
			)
		} else {
			return fmt.Errorf(
				"could not find runtime %s; tried: %s",
				opts.Project.Runtime().Name(),
				tried,
			)
		}
	} else if len(packs) == 1 {
		selected = &packs[0]
	} else if len(packs) > 1 {
		sort.Slice(packs, func(i, j int) bool {
			if packs[i].Name() == packs[j].Name() {
				return packs[i].Version() < packs[j].Version()
			}
			return packs[i].Name() < packs[j].Name()
		})
		selected = &packs[0]
		log.G(ctx).WithFields(map[string]interface{}{
			"runtime_query":    formatRuntimeReference(resolved),
			"selected_runtime": (*selected).String(),
			"candidates":       len(packs),
		}).Info("multiple runtimes available; selecting first compatible candidate")
	}

	targ := (*selected).(target.Target)
	opts.Target = &targ

	return nil
}

func queryRuntimeCandidates(
	ctx context.Context,
	candidates []runtimeutil.Reference,
	qopts []packmanager.QueryOption,
) ([]pack.Package, runtimeutil.Reference, error) {
	var queryErr error
	for _, candidate := range candidates {
		options := append([]packmanager.QueryOption{}, qopts...)
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

func composeRuntimeRef(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return fmt.Sprintf("%s:%s", name, version)
}

func joinRuntimeCandidates(candidates []runtimeutil.Reference) string {
	if len(candidates) == 0 {
		return "-"
	}

	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, formatRuntimeReference(candidate))
	}

	return strings.Join(values, ", ")
}

func formatRuntimeReference(candidate runtimeutil.Reference) string {
	value := candidate.String()
	if value == "" {
		return "-"
	}
	return value
}

func (*builderKraftfileRuntime) Build(_ context.Context, _ *BuildOptions, _ ...string) error {
	return nil
}

func (*builderKraftfileRuntime) Statistics(ctx context.Context, opts *BuildOptions, args ...string) error {
	return fmt.Errorf("cannot calculate statistics of pre-built unikernel runtime")
}
