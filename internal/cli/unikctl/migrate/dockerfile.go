// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package migrate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"unikctl.sh/cmdfactory"
	"unikctl.sh/internal/runtimeutil"
)

type DockerfileOptions struct {
	Output string `long:"output" short:"o" usage:"Write generated unik config to this file path"`
	Force  bool   `long:"force" usage:"Overwrite output file if it already exists"`
}

type dockerfileMetadata struct {
	From       string
	Workdir    string
	Entrypoint []string
	Cmd        []string
	Expose     []string
	Env        map[string]string
}

type migratedUnikConfig struct {
	Version  string `yaml:"version"`
	Language string `yaml:"language,omitempty"`
	Runtime  string `yaml:"runtime,omitempty"`
	Run      struct {
		Command []string `yaml:"command,omitempty"`
	} `yaml:"run,omitempty"`
}

func newDockerfileCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&DockerfileOptions{}, cobra.Command{
		Use:   "dockerfile [DOCKERFILE|DIR]",
		Short: "Convert a Dockerfile into unikctl-compatible config",
		Args:  cobra.MaximumNArgs(1),
		Example: `  unikctl migrate dockerfile
  unikctl migrate dockerfile ./Dockerfile
  unikctl migrate dockerfile ./my-app --output ./my-app/unik.yaml`,
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *DockerfileOptions) Run(ctx context.Context, args []string) error {
	input, dockerfilePath, err := resolveDockerfileInput(args)
	if err != nil {
		return err
	}

	meta, err := parseDockerfile(dockerfilePath)
	if err != nil {
		return err
	}

	config := toMigratedUnikConfig(meta)
	outputPath, err := resolveDockerfileOutputPath(input, opts.Output)
	if err != nil {
		return err
	}

	if err := writeMigratedUnikConfig(config, outputPath, opts.Force); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "migrated Dockerfile %s -> %s\n", dockerfilePath, outputPath)
	if meta.From != "" {
		fmt.Fprintf(os.Stdout, "detected base image: %s\n", meta.From)
	}
	if config.Language != "" {
		fmt.Fprintf(os.Stdout, "detected language: %s\n", config.Language)
	}
	if config.Runtime != "" {
		fmt.Fprintf(os.Stdout, "normalized runtime: %s\n", config.Runtime)
	}
	if len(config.Run.Command) > 0 {
		fmt.Fprintf(os.Stdout, "detected startup command: %s\n", strings.Join(config.Run.Command, " "))
	}
	fmt.Fprintf(os.Stdout, "next step: run `unikctl build %s` and `unikctl deploy %s`\n", input, input)
	return nil
}

func resolveDockerfileInput(args []string) (string, string, error) {
	input := "."
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		input = strings.TrimSpace(args[0])
	}

	absInput, err := filepath.Abs(input)
	if err != nil {
		return "", "", err
	}

	stat, err := os.Stat(absInput)
	if err != nil {
		return "", "", err
	}

	if stat.IsDir() {
		candidate := filepath.Join(absInput, "Dockerfile")
		if _, err := os.Stat(candidate); err != nil {
			return "", "", fmt.Errorf("could not find Dockerfile in %s", absInput)
		}
		return absInput, candidate, nil
	}

	return filepath.Dir(absInput), absInput, nil
}

func resolveDockerfileOutputPath(workdir, output string) (string, error) {
	if strings.TrimSpace(output) != "" {
		return filepath.Abs(strings.TrimSpace(output))
	}

	defaultPath := filepath.Join(workdir, "unik.yaml")
	if _, err := os.Stat(defaultPath); err == nil {
		return filepath.Join(workdir, "unik.migrated.yaml"), nil
	}

	return defaultPath, nil
}

func parseDockerfile(path string) (*dockerfileMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening Dockerfile: %w", err)
	}
	defer file.Close()

	meta := &dockerfileMetadata{
		Env: map[string]string{},
	}

	lines := joinContinuationLines(file)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		instruction, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}

		switch strings.ToUpper(strings.TrimSpace(instruction)) {
		case "FROM":
			meta.From = firstToken(value)
		case "WORKDIR":
			meta.Workdir = strings.TrimSpace(value)
		case "ENV":
			mergeEnv(meta.Env, value)
		case "EXPOSE":
			meta.Expose = append(meta.Expose, parseExpose(value)...)
		case "ENTRYPOINT":
			meta.Entrypoint = parseDockerCommandValue(value)
		case "CMD":
			meta.Cmd = parseDockerCommandValue(value)
		}
	}

	return meta, nil
}

func joinContinuationLines(file *os.File) []string {
	scanner := bufio.NewScanner(file)
	lines := []string{}
	current := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, "\\") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
			current = strings.TrimSpace(current + " " + line)
			continue
		}

		if current != "" {
			line = strings.TrimSpace(current + " " + line)
			current = ""
		}

		lines = append(lines, line)
	}

	if current != "" {
		lines = append(lines, strings.TrimSpace(current))
	}

	return lines
}

func parseDockerCommandValue(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if strings.HasPrefix(value, "[") {
		ret := []string{}
		if err := json.Unmarshal([]byte(value), &ret); err == nil {
			return ret
		}
	}

	return []string{"sh", "-lc", value}
}

func mergeEnv(env map[string]string, value string) {
	for _, token := range strings.Fields(strings.TrimSpace(value)) {
		key, val, ok := strings.Cut(token, "=")
		if ok {
			env[strings.TrimSpace(key)] = strings.TrimSpace(val)
			continue
		}
	}
}

func parseExpose(value string) []string {
	ports := []string{}
	for _, token := range strings.Fields(strings.TrimSpace(value)) {
		token = strings.TrimSpace(token)
		if token != "" {
			ports = append(ports, token)
		}
	}
	return ports
}

func firstToken(value string) string {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func toMigratedUnikConfig(meta *dockerfileMetadata) migratedUnikConfig {
	out := migratedUnikConfig{
		Version: "v1",
	}

	lang := guessLanguage(meta.From)
	out.Language = lang

	runtime := guessRuntime(lang)
	if runtime == "" && meta.From != "" {
		runtime = normalizeRuntimeFromBaseImage(meta.From)
	}
	out.Runtime = runtime

	if len(meta.Entrypoint) > 0 {
		out.Run.Command = append(out.Run.Command, meta.Entrypoint...)
		if len(meta.Cmd) > 0 {
			out.Run.Command = append(out.Run.Command, meta.Cmd...)
		}
	} else if len(meta.Cmd) > 0 {
		out.Run.Command = append(out.Run.Command, meta.Cmd...)
	}

	return out
}

func guessLanguage(baseImage string) string {
	lower := strings.ToLower(strings.TrimSpace(baseImage))
	switch {
	case strings.Contains(lower, "node"):
		return "node"
	case strings.Contains(lower, "python"):
		return "python"
	case strings.Contains(lower, "golang"), strings.Contains(lower, "/go"):
		return "go"
	case strings.Contains(lower, "rust"):
		return "rust"
	case strings.Contains(lower, "openjdk"), strings.Contains(lower, "java"):
		return "java"
	case strings.Contains(lower, "dotnet"), strings.Contains(lower, "aspnet"):
		return "dotnet"
	default:
		return ""
	}
}

func guessRuntime(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "node":
		return runtimeutil.Normalize("nodejs", "latest")
	case "python":
		return runtimeutil.Normalize("python", "latest")
	case "java":
		return runtimeutil.Normalize("java", "latest")
	case "dotnet":
		return runtimeutil.Normalize("dotnet", "latest")
	case "go", "rust":
		return runtimeutil.Normalize("base", "latest")
	default:
		return ""
	}
}

func normalizeRuntimeFromBaseImage(baseImage string) string {
	ref := strings.TrimSpace(baseImage)
	if ref == "" {
		return ""
	}

	name := ref
	if idx := strings.LastIndex(ref, ":"); idx > strings.LastIndex(ref, "/") {
		name = ref[:idx]
	}

	short := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 && idx < len(name)-1 {
		short = name[idx+1:]
	}

	return runtimeutil.Normalize(short, "latest")
}

func writeMigratedUnikConfig(config migratedUnikConfig, outputPath string, force bool) error {
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file already exists: %s (use --force to overwrite)", outputPath)
		}
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshalling migrated unik config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing migrated unik config: %w", err)
	}

	return nil
}
