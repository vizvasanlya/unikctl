// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"unikctl.sh/internal/runtimeutil"
)

type runtimeConfig struct {
	Version string `yaml:"version,omitempty"`
	Runtime string `yaml:"runtime,omitempty"`
	Rootfs  struct {
		Source string `yaml:"source,omitempty"`
		Type   string `yaml:"type,omitempty"`
	} `yaml:"rootfs,omitempty"`
	Run struct {
		Command []string `yaml:"command,omitempty"`
	} `yaml:"run,omitempty"`
}

func main() {
	root := flag.String("root", "runtimes", "Runtime source root directory")
	runtimesCSV := flag.String("runtimes", "base,nodejs,python,java,dotnet", "Comma-separated runtimes to validate")
	flag.Parse()

	var failures []string
	for _, runtimeName := range splitCSV(*runtimesCSV) {
		if runtimeName == "" {
			continue
		}

		if err := validateRuntimeSource(*root, runtimeName); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", runtimeName, err))
			continue
		}

		fmt.Printf("ok: %s\n", runtimeName)
	}

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "runtime source validation failed:")
		for _, failure := range failures {
			fmt.Fprintf(os.Stderr, " - %s\n", failure)
		}
		os.Exit(1)
	}
}

func validateRuntimeSource(root, runtimeName string) error {
	runtimeDir := filepath.Join(root, runtimeName)
	info, err := os.Stat(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("missing runtime directory %s", runtimeDir)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime source path is not a directory: %s", runtimeDir)
	}

	cfgPath := filepath.Join(runtimeDir, "unik.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", cfgPath, err)
	}

	cfg := runtimeConfig{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parsing %s: %w", cfgPath, err)
	}

	if strings.TrimSpace(cfg.Version) == "" {
		return fmt.Errorf("unik.yaml requires version")
	}

	if strings.TrimSpace(cfg.Runtime) == "" {
		return fmt.Errorf("unik.yaml requires runtime")
	}
	if !strings.HasPrefix(strings.TrimSpace(cfg.Runtime), runtimeutil.RuntimeRegistryPrefix+"/") {
		return fmt.Errorf("runtime must stay under %s, got %s", runtimeutil.RuntimeRegistryPrefix, cfg.Runtime)
	}

	rootfsSource := strings.TrimSpace(cfg.Rootfs.Source)
	if rootfsSource == "" {
		return fmt.Errorf("unik.yaml requires rootfs.source")
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, rootfsSource)); err != nil {
		return fmt.Errorf("rootfs.source does not exist: %s", rootfsSource)
	}

	rootfsType := strings.TrimSpace(cfg.Rootfs.Type)
	if rootfsType == "" {
		return fmt.Errorf("unik.yaml requires rootfs.type")
	}
	switch rootfsType {
	case "cpio", "erofs":
	default:
		return fmt.Errorf("unsupported rootfs.type %q (allowed: cpio, erofs)", rootfsType)
	}

	return nil
}

func splitCSV(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
