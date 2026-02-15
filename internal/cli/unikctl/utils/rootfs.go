// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"unikctl.sh/config"
	"unikctl.sh/initrd"
	"unikctl.sh/log"
	"unikctl.sh/tui/processtree"
	"unikctl.sh/unikraft"
)

// BuildRootfs generates a rootfs based on the provided working directory and
// the rootfs entrypoint for the provided target(s).
func BuildRootfs(ctx context.Context, workdir, rootfs string, compress, keepOwners bool, arch string, fsType initrd.FsType) (initrd.Initrd, []string, []string, error) {
	if rootfs == "" || fsType == "" {
		return nil, nil, nil, nil
	}

	rootfsSourcePath := rootfs
	if !filepath.IsAbs(rootfsSourcePath) {
		rootfsSourcePath = filepath.Join(workdir, rootfsSourcePath)
	}
	rootfsSourcePath = filepath.Clean(rootfsSourcePath)

	outputPath := filepath.Join(
		workdir,
		unikraft.BuildDir,
		fmt.Sprintf(initrd.DefaultInitramfsArchFileName, arch, fsType),
	)
	cachePath := outputPath + ".meta.json"

	if reused, ok, err := tryReuseRootfsArchive(ctx, workdir, rootfsSourcePath, outputPath, arch, fsType, compress, keepOwners); err != nil {
		log.G(ctx).WithError(err).Debug("could not evaluate rootfs archive cache, rebuilding")
	} else if ok {
		log.G(ctx).WithFields(map[string]interface{}{
			"output": outputPath,
			"source": rootfsSourcePath,
		}).Info("reusing cached rootfs archive")
		return reused, nil, nil, nil
	}

	var processes []*processtree.ProcessTreeItem
	var cmds []string
	var envs []string

	ramfs, err := initrd.New(ctx,
		rootfsSourcePath,
		initrd.WithWorkdir(workdir),
		initrd.WithOutput(outputPath),
		initrd.WithCacheDir(filepath.Join(
			workdir,
			unikraft.VendorDir,
			"rootfs-cache",
		)),
		initrd.WithArchitecture(arch),
		initrd.WithCompression(compress),
		initrd.WithKeepOwners(keepOwners),
		initrd.WithOutputType(fsType),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize initramfs builder: %w", err)
	}

	processes = append(processes,
		processtree.NewProcessTreeItem(
			fmt.Sprintf("building rootfs via %s", ramfs.Name()),
			arch,
			func(ctx context.Context) error {
				rootfs, err = ramfs.Build(ctx)
				if err != nil {
					return err
				}

				// Always overwrite the existing cmds and envs, considering this will
				// be the same regardless of the target.
				cmds = ramfs.Args()
				envs = ramfs.Env()

				if err := persistRootfsArchiveCache(rootfsSourcePath, outputPath, cachePath, arch, fsType, compress, keepOwners); err != nil {
					log.G(ctx).WithError(err).Debug("could not persist rootfs archive cache metadata")
				}

				return nil
			},
		),
	)

	model, err := processtree.NewProcessTree(
		ctx,
		[]processtree.ProcessTreeOption{
			processtree.IsParallel(false),
			processtree.WithRenderer(log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) != log.FANCY),
		},
		processes...,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := model.Start(); err != nil {
		return nil, nil, nil, err
	}

	return ramfs, cmds, envs, nil
}

type rootfsArchiveCache struct {
	SourcePath       string `json:"source_path"`
	SourceLatestUnix int64  `json:"source_latest_unix"`
	Arch             string `json:"arch"`
	FsType           string `json:"fs_type"`
	Compress         bool   `json:"compress"`
	KeepOwners       bool   `json:"keep_owners"`
}

func tryReuseRootfsArchive(ctx context.Context, workdir, sourcePath, outputPath, arch string, fsType initrd.FsType, compress, keepOwners bool) (initrd.Initrd, bool, error) {
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil || !sourceInfo.IsDir() {
		return nil, false, nil
	}

	if _, err := os.Stat(outputPath); err != nil {
		return nil, false, nil
	}

	cachePath := outputPath + ".meta.json"
	cache, err := loadRootfsArchiveCache(cachePath)
	if err != nil {
		return nil, false, nil
	}

	if cache.SourcePath != sourcePath ||
		cache.Arch != strings.TrimSpace(arch) ||
		cache.FsType != fsType.String() ||
		cache.Compress != compress ||
		cache.KeepOwners != keepOwners {
		return nil, false, nil
	}

	latest, err := latestDirectoryModTime(sourcePath)
	if err != nil {
		return nil, false, err
	}

	if cache.SourceLatestUnix != latest.Unix() {
		return nil, false, nil
	}

	ramfs, err := initrd.New(ctx,
		outputPath,
		initrd.WithWorkdir(workdir),
		initrd.WithOutputType(fsType),
	)
	if err != nil {
		return nil, false, err
	}

	return ramfs, true, nil
}

func persistRootfsArchiveCache(sourcePath, outputPath, cachePath, arch string, fsType initrd.FsType, compress, keepOwners bool) error {
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil || !sourceInfo.IsDir() {
		return nil
	}

	latest, err := latestDirectoryModTime(sourcePath)
	if err != nil {
		return err
	}

	cache := rootfsArchiveCache{
		SourcePath:       sourcePath,
		SourceLatestUnix: latest.Unix(),
		Arch:             strings.TrimSpace(arch),
		FsType:           fsType.String(),
		Compress:         compress,
		KeepOwners:       keepOwners,
	}

	raw, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	return os.WriteFile(cachePath, raw, 0o644)
}

func loadRootfsArchiveCache(path string) (*rootfsArchiveCache, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cache := &rootfsArchiveCache{}
	if err := json.Unmarshal(raw, cache); err != nil {
		return nil, err
	}

	return cache, nil
}

func latestDirectoryModTime(root string) (time.Time, error) {
	latest := time.Time{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}

		return nil
	})
	if err != nil {
		return time.Time{}, err
	}

	return latest.UTC(), nil
}

// BuildRoms generates ROM filesystems based on the provided ROM paths.
func BuildRoms(ctx context.Context, workdir string, roms []string, compress, keepOwners bool, arch string, fsType initrd.FsType) ([]string, error) {
	if len(roms) == 0 || fsType == "" {
		return roms, nil
	}

	var processes []*processtree.ProcessTreeItem
	builtRoms := make([]string, len(roms))
	for i, rom := range roms {
		// Check if the ROM is a directory; if it's a file, skip building and use as-is
		romPath := rom
		if !filepath.IsAbs(rom) {
			romPath = filepath.Join(workdir, rom)
		}

		info, err := os.Stat(romPath)
		if err != nil {
			return nil, fmt.Errorf("could not stat ROM path '%s': %w", rom, err)
		}

		// If it's a regular file, don't try to build it as a filesystem
		if !info.IsDir() {
			// File ROMs must be aligned to page size
			const pageSize = 4096
			if info.Size()%pageSize != 0 {
				return nil, fmt.Errorf("ROM file '%s' size (%d bytes) is not aligned to page size (%d bytes)", rom, info.Size(), pageSize)
			}
			builtRoms[i] = rom
			continue
		}

		ramfs, err := initrd.New(ctx,
			rom,
			initrd.WithWorkdir(workdir),
			initrd.WithOutput(filepath.Join(
				workdir,
				unikraft.BuildDir,
				fmt.Sprintf("rom%d-%s.%s", i+1, arch, fsType),
			)),
			initrd.WithCacheDir(filepath.Join(
				workdir,
				unikraft.VendorDir,
				"rom-cache",
			)),
			initrd.WithArchitecture(arch),
			initrd.WithCompression(compress),
			initrd.WithKeepOwners(keepOwners),
			initrd.WithOutputType(fsType),
		)
		if err != nil {
			return nil, fmt.Errorf("could not initialize ROM builder for '%s': %w", rom, err)
		}

		processes = append(processes,
			processtree.NewProcessTreeItem(
				fmt.Sprintf("building ROM %d via %s", i+1, ramfs.Name()),
				arch,
				func(ctx context.Context) error {
					builtRom, err := ramfs.Build(ctx)
					if err != nil {
						return err
					}

					builtRoms[i] = builtRom
					return nil
				},
			),
		)
	}

	// Only run the process tree if there are directories to build
	if len(processes) > 0 {
		model, err := processtree.NewProcessTree(
			ctx,
			[]processtree.ProcessTreeOption{
				processtree.IsParallel(false),
				processtree.WithRenderer(log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) != log.FANCY),
			},
			processes...,
		)
		if err != nil {
			return nil, err
		}

		if err := model.Start(); err != nil {
			return nil, err
		}
	}

	return builtRoms, nil
}
