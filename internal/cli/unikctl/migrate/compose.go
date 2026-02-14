// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"unikctl.sh/cmdfactory"
)

type ComposeOptions struct {
	Output string `long:"output" short:"o" usage:"Write compose migration plan to this file path"`
	Force  bool   `long:"force" usage:"Overwrite output file if it already exists"`
}

type dockerComposeFile struct {
	Version  string                          `yaml:"version,omitempty"`
	Services map[string]dockerComposeService `yaml:"services,omitempty"`
}

type dockerComposeService struct {
	Image       string      `yaml:"image,omitempty"`
	Build       interface{} `yaml:"build,omitempty"`
	Command     interface{} `yaml:"command,omitempty"`
	Entrypoint  interface{} `yaml:"entrypoint,omitempty"`
	Environment interface{} `yaml:"environment,omitempty"`
	Ports       []string    `yaml:"ports,omitempty"`
	WorkingDir  string      `yaml:"working_dir,omitempty"`
}

type migratedComposePlan struct {
	Version     string                      `yaml:"version"`
	Source      string                      `yaml:"source"`
	GeneratedAt string                      `yaml:"generated_at"`
	Services    []migratedComposePlanRecord `yaml:"services"`
}

type migratedComposePlanRecord struct {
	Name            string            `yaml:"name"`
	SourcePath      string            `yaml:"source_path,omitempty"`
	Image           string            `yaml:"image,omitempty"`
	GeneratedConfig string            `yaml:"generated_unik_yaml,omitempty"`
	DeployCommand   string            `yaml:"deploy_command"`
	RunCommand      []string          `yaml:"run_command,omitempty"`
	Ports           []string          `yaml:"ports,omitempty"`
	Environment     map[string]string `yaml:"environment,omitempty"`
	Notes           []string          `yaml:"notes,omitempty"`
}

func newComposeCmd() *cobra.Command {
	cmd, err := cmdfactory.New(&ComposeOptions{}, cobra.Command{
		Use:   "compose [COMPOSE_FILE]",
		Short: "Convert docker-compose.yml into unikctl migration plan",
		Args:  cobra.MaximumNArgs(1),
		Example: `  unikctl migrate compose
  unikctl migrate compose ./docker-compose.yml
  unikctl migrate compose ./compose.yml --output ./unikctl-compose.migrated.yaml`,
	})
	if err != nil {
		panic(err)
	}

	return cmd
}

func (opts *ComposeOptions) Run(ctx context.Context, args []string) error {
	composePath, err := resolveComposePath(args)
	if err != nil {
		return err
	}

	composeDoc, err := readComposeFile(composePath)
	if err != nil {
		return err
	}

	composeDir := filepath.Dir(composePath)
	plan := migratedComposePlan{
		Version:     "v1",
		Source:      composePath,
		GeneratedAt: strings.TrimSpace(nowUTC()),
		Services:    []migratedComposePlanRecord{},
	}

	serviceNames := make([]string, 0, len(composeDoc.Services))
	for name := range composeDoc.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, serviceName := range serviceNames {
		service := composeDoc.Services[serviceName]
		record := migratedComposePlanRecord{
			Name:        serviceName,
			Image:       strings.TrimSpace(service.Image),
			Ports:       append([]string{}, service.Ports...),
			Environment: parseComposeEnv(service.Environment),
			Notes:       []string{},
		}

		entrypoint := parseComposeCommandValue(service.Entrypoint)
		command := parseComposeCommandValue(service.Command)
		if len(entrypoint) > 0 {
			record.RunCommand = append(record.RunCommand, entrypoint...)
			if len(command) > 0 {
				record.RunCommand = append(record.RunCommand, command...)
			}
		} else {
			record.RunCommand = append(record.RunCommand, command...)
		}

		contextPath, dockerfileName := parseComposeBuildSpec(service.Build)
		if contextPath != "" {
			absContext := filepath.Join(composeDir, filepath.Clean(contextPath))
			if info, err := os.Stat(absContext); err == nil && info.IsDir() {
				record.SourcePath = absContext

				dockerfilePath := filepath.Join(absContext, firstNonEmpty(dockerfileName, "Dockerfile"))
				if _, err := os.Stat(dockerfilePath); err == nil {
					generatedPath, genErr := migrateServiceDockerfile(absContext, dockerfilePath, serviceName)
					if genErr != nil {
						record.Notes = append(record.Notes, fmt.Sprintf("could not generate unik config from %s: %v", dockerfilePath, genErr))
					} else {
						record.GeneratedConfig = generatedPath
					}
				} else {
					record.Notes = append(record.Notes, fmt.Sprintf("build context %s has no %s", absContext, firstNonEmpty(dockerfileName, "Dockerfile")))
				}
			} else {
				record.Notes = append(record.Notes, fmt.Sprintf("build context path not found: %s", absContext))
			}
		}

		deploySource := firstNonEmpty(record.SourcePath, ".")
		record.DeployCommand = fmt.Sprintf("unikctl deploy %s --name %s", deploySource, serviceName)

		if record.SourcePath == "" && record.Image != "" {
			record.Notes = append(record.Notes, "service has image only; verify image is unikernel-compatible before deploy")
			record.DeployCommand = fmt.Sprintf("unikctl deploy %s --name %s", record.Image, serviceName)
		}

		plan.Services = append(plan.Services, record)
	}

	outputPath, err := resolveComposeOutputPath(composeDir, opts.Output)
	if err != nil {
		return err
	}

	if err := writeComposePlan(plan, outputPath, opts.Force); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "migrated compose file %s -> %s\n", composePath, outputPath)
	for _, svc := range plan.Services {
		fmt.Fprintf(os.Stdout, "service %s: %s\n", svc.Name, svc.DeployCommand)
		if svc.GeneratedConfig != "" {
			fmt.Fprintf(os.Stdout, "  generated config: %s\n", svc.GeneratedConfig)
		}
	}
	return nil
}

func resolveComposePath(args []string) (string, error) {
	input := "docker-compose.yml"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		input = strings.TrimSpace(args[0])
	}

	abs, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("could not find compose file: %s", abs)
	}

	return abs, nil
}

func readComposeFile(path string) (*dockerComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading compose file: %w", err)
	}

	doc := &dockerComposeFile{}
	if err := yaml.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("parsing compose file: %w", err)
	}

	if len(doc.Services) == 0 {
		return nil, fmt.Errorf("compose file contains no services")
	}

	return doc, nil
}

func parseComposeBuildSpec(value interface{}) (string, string) {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed), ""
	case map[string]interface{}:
		contextPath := ""
		dockerfileName := ""
		if raw, ok := typed["context"]; ok {
			contextPath = strings.TrimSpace(fmt.Sprintf("%v", raw))
		}
		if raw, ok := typed["dockerfile"]; ok {
			dockerfileName = strings.TrimSpace(fmt.Sprintf("%v", raw))
		}
		return contextPath, dockerfileName
	case map[interface{}]interface{}:
		contextPath := ""
		dockerfileName := ""
		for key, raw := range typed {
			k := strings.TrimSpace(fmt.Sprintf("%v", key))
			switch k {
			case "context":
				contextPath = strings.TrimSpace(fmt.Sprintf("%v", raw))
			case "dockerfile":
				dockerfileName = strings.TrimSpace(fmt.Sprintf("%v", raw))
			}
		}
		return contextPath, dockerfileName
	default:
		return "", ""
	}
}

func parseComposeCommandValue(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return nil
		}
		return []string{"sh", "-lc", typed}
	case []interface{}:
		ret := make([]string, 0, len(typed))
		for _, item := range typed {
			ret = append(ret, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
		return ret
	case []string:
		ret := make([]string, 0, len(typed))
		for _, item := range typed {
			ret = append(ret, strings.TrimSpace(item))
		}
		return ret
	default:
		return []string{strings.TrimSpace(fmt.Sprintf("%v", typed))}
	}
}

func parseComposeEnv(value interface{}) map[string]string {
	env := map[string]string{}

	switch typed := value.(type) {
	case map[string]interface{}:
		for key, raw := range typed {
			env[strings.TrimSpace(key)] = strings.TrimSpace(fmt.Sprintf("%v", raw))
		}
	case map[interface{}]interface{}:
		for key, raw := range typed {
			env[strings.TrimSpace(fmt.Sprintf("%v", key))] = strings.TrimSpace(fmt.Sprintf("%v", raw))
		}
	case []interface{}:
		for _, raw := range typed {
			entry := strings.TrimSpace(fmt.Sprintf("%v", raw))
			key, val, ok := strings.Cut(entry, "=")
			if !ok {
				env[entry] = ""
				continue
			}
			env[strings.TrimSpace(key)] = strings.TrimSpace(val)
		}
	}

	return env
}

func migrateServiceDockerfile(contextPath, dockerfilePath, serviceName string) (string, error) {
	meta, err := parseDockerfile(dockerfilePath)
	if err != nil {
		return "", err
	}

	config := toMigratedUnikConfig(meta)
	defaultPath := filepath.Join(contextPath, "unik.yaml")
	outputPath := defaultPath
	if _, err := os.Stat(defaultPath); err == nil {
		outputPath = filepath.Join(contextPath, fmt.Sprintf("unik.%s.yaml", serviceName))
	}

	if err := writeMigratedUnikConfig(config, outputPath, true); err != nil {
		return "", err
	}

	return outputPath, nil
}

func resolveComposeOutputPath(composeDir, output string) (string, error) {
	if strings.TrimSpace(output) != "" {
		return filepath.Abs(strings.TrimSpace(output))
	}

	return filepath.Join(composeDir, "unikctl-compose.migrated.yaml"), nil
}

func writeComposePlan(plan migratedComposePlan, outputPath string, force bool) error {
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file already exists: %s (use --force to overwrite)", outputPath)
		}
	}

	data, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshalling compose migration plan: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing compose migration plan: %w", err)
	}

	return nil
}
