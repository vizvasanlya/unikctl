// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"unikctl.sh/config"
	"unikctl.sh/internal/bootstrap"
	"unikctl.sh/internal/cli"
	pkgcmd "unikctl.sh/internal/cli/unikctl/pkg"
	"unikctl.sh/internal/runtimeutil"
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

	sourceDir := strings.TrimSpace(*source)
	kraftfilePath, err := ensureRuntimeProjectManifest(sourceDir, strings.TrimSpace(*name))
	if err != nil {
		fatalf("preparing runtime project manifest: %v", err)
	}
	if kraftfilePath != "" {
		defer os.Remove(kraftfilePath)
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
		Kraftfile:    kraftfilePath,
		Name:         strings.TrimSpace(*name),
		NoPull:       false,
		Platform:     strings.TrimSpace(*plat),
		Push:         *push,
		Strategy:     packmanager.StrategyMerge,
		Workdir:      sourceDir,
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

type runtimeSourceConfig struct {
	Runtime string `yaml:"runtime,omitempty"`
	Rootfs  struct {
		Source string `yaml:"source,omitempty"`
		Type   string `yaml:"type,omitempty"`
	} `yaml:"rootfs,omitempty"`
	Run struct {
		Command []string `yaml:"command,omitempty"`
	} `yaml:"run,omitempty"`
	Cmd []string `yaml:"cmd,omitempty"`
}

type generatedKraftfile struct {
	Spec    string                `yaml:"spec"`
	Runtime string                `yaml:"runtime,omitempty"`
	Rootfs  *generatedKraftfileFS `yaml:"rootfs,omitempty"`
	Cmd     []string              `yaml:"cmd,omitempty"`
}

type generatedKraftfileFS struct {
	Source string `yaml:"source,omitempty"`
	Type   string `yaml:"type,omitempty"`
}

func ensureRuntimeProjectManifest(sourceDir, imageRef string) (string, error) {
	if sourceDir == "" {
		return "", fmt.Errorf("missing source directory")
	}

	// Keep native project manifests first-class and avoid exposing Kraftfile in UX.
	kraftfilePath := filepath.Join(sourceDir, "Kraftfile")
	if _, err := os.Stat(kraftfilePath); err == nil {
		return "", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking Kraftfile: %w", err)
	}

	cfg := runtimeSourceConfig{}
	unikYAMLPath := filepath.Join(sourceDir, "unik.yaml")
	if data, err := os.ReadFile(unikYAMLPath); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return "", fmt.Errorf("parsing unik.yaml: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("reading unik.yaml: %w", err)
	}

	rootfsSource := strings.TrimSpace(cfg.Rootfs.Source)
	if rootfsSource == "" {
		if _, err := os.Stat(filepath.Join(sourceDir, "Dockerfile")); err == nil {
			rootfsSource = "Dockerfile"
		}
	}

	runtime := strings.TrimSpace(cfg.Runtime)
	imageName := runtimeImageShortName(imageRef)
	if runtime == "" && imageName != "base" {
		runtime = runtimeutil.RuntimeRegistryPrefix + "/base:latest"
	}

	generated := generatedKraftfile{
		Spec:    "v0.6",
		Runtime: runtime,
	}

	if rootfsSource != "" {
		fsType := strings.TrimSpace(cfg.Rootfs.Type)
		if fsType == "" {
			fsType = "cpio"
		}
		generated.Rootfs = &generatedKraftfileFS{
			Source: rootfsSource,
			Type:   fsType,
		}
	}

	if len(cfg.Run.Command) > 0 {
		generated.Cmd = cfg.Run.Command
	} else if len(cfg.Cmd) > 0 {
		generated.Cmd = cfg.Cmd
	}

	out, err := yaml.Marshal(generated)
	if err != nil {
		return "", fmt.Errorf("marshalling generated Kraftfile: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "unikctl-runtime-*.Kraftfile")
	if err != nil {
		return "", fmt.Errorf("creating temporary Kraftfile: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(out); err != nil {
		return "", fmt.Errorf("writing temporary Kraftfile: %w", err)
	}

	return tmpFile.Name(), nil
}

func runtimeImageShortName(imageRef string) string {
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		return ""
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(ref))
}
