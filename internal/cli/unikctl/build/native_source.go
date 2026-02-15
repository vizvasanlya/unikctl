// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The unikctl Authors.

package build

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"unikctl.sh/internal/runtimeutil"
	"unikctl.sh/log"
)

type nativeProjectConfig struct {
	Version  string `yaml:"version,omitempty"`
	Language string `yaml:"language,omitempty"`
	Runtime  string `yaml:"runtime,omitempty"`
	Build    struct {
		Command string `yaml:"command,omitempty"`
	} `yaml:"build,omitempty"`
	Run struct {
		Command []string `yaml:"command,omitempty"`
	} `yaml:"run,omitempty"`
	Artifact struct {
		Path string `yaml:"path,omitempty"`
	} `yaml:"artifact,omitempty"`
}

type nodePackageManifest struct {
	Main            string            `json:"main,omitempty"`
	Scripts         map[string]string `json:"scripts,omitempty"`
	Dependencies    map[string]string `json:"dependencies,omitempty"`
	DevDependencies map[string]string `json:"devDependencies,omitempty"`
	Unikctl         struct {
		Dist string `json:"dist,omitempty"`
	} `json:"unikctl,omitempty"`
}

type pyprojectManifest struct {
	Project struct {
		Scripts map[string]string `toml:"scripts"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Scripts map[string]string `toml:"scripts"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

type generatedKraftfile struct {
	Spec    string   `yaml:"spec"`
	Runtime string   `yaml:"runtime"`
	Cmd     []string `yaml:"cmd,omitempty"`
}

type nativeBuildResult struct {
	Runtime string
	Command []string
}

type nativePipelineResult struct {
	RootfsDir string
	Kraftfile string
	Runtime   string
	Command   []string
	Pack      string
}

type nativePackMetadata struct {
	LayoutVersion  int       `json:"layout_version"`
	LanguagePack   string    `json:"language_pack"`
	BuildMode      string    `json:"build_mode"`
	Runtime        string    `json:"runtime"`
	Command        []string  `json:"command"`
	RootfsDir      string    `json:"rootfs_dir"`
	Deterministic  bool      `json:"deterministic"`
	GeneratedAtUTC time.Time `json:"generated_at_utc"`
}

const nativePipelineLayoutVersion = 2

type nativeLanguagePack interface {
	Name() string
	Detect(string) bool
	Build(context.Context, *BuildOptions, string, string, *nativeProjectConfig) (*nativeBuildResult, error)
}

func (opts *BuildOptions) prepareNativeSourceProject(ctx context.Context) error {
	if isDockerfilePath(opts.Rootfs) {
		return fmt.Errorf("dockerfile-based rootfs is disabled: provide source code or unik.yaml")
	}

	initErr := opts.initProject(ctx)
	if initErr == nil {
		if opts.Project != nil && isDockerfilePath(opts.Project.Rootfs()) {
			return fmt.Errorf("dockerfile-based rootfs in Kraftfile is disabled: use source pipeline")
		}

		// If a project is present but no rootfs is configured, synthesize one from source.
		if opts.Project != nil && opts.Project.Rootfs() == "" && opts.Rootfs == "" {
			res, err := runNativeSourcePipeline(ctx, opts)
			if err != nil {
				return err
			}

			opts.Rootfs = res.RootfsDir

			// If runtime is not defined in the project, switch to generated Kraftfile.
			if opts.Project.Runtime() == nil || opts.Project.Runtime().Name() == "" {
				opts.Kraftfile = res.Kraftfile
				if err := opts.initProject(ctx); err != nil {
					return fmt.Errorf("could not initialize generated project: %w", err)
				}
			}
		}

		return nil
	}

	// No project definition found: fall back to native source pipeline and generate one.
	res, pipeErr := runNativeSourcePipeline(ctx, opts)
	if pipeErr != nil {
		return fmt.Errorf("could not initialize project (%v) and native source pipeline failed: %w", initErr, pipeErr)
	}

	opts.Kraftfile = res.Kraftfile
	opts.Rootfs = res.RootfsDir

	if err := opts.initProject(ctx); err != nil {
		return fmt.Errorf("could not initialize generated project: %w", err)
	}

	return nil
}

func runNativeSourcePipeline(ctx context.Context, opts *BuildOptions) (*nativePipelineResult, error) {
	cfg, err := loadNativeProjectConfig(opts.Workdir)
	if err != nil {
		return nil, err
	}

	pack, err := selectNativePack(opts.Workdir, cfg)
	if err != nil {
		return nil, err
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"language_pack": pack.Name(),
		"mode":          buildMode(opts),
	}).Info("native source pipeline selected")

	stageDir := filepath.Join(opts.Workdir, ".unikctl", "native")
	rootfsDir := filepath.Join(stageDir, "rootfs")
	kraftfilePath := filepath.Join(stageDir, "Kraftfile")

	if cached, ok, err := tryReuseNativePipeline(ctx, opts.Workdir, stageDir, pack.Name(), buildMode(opts)); err != nil {
		log.G(ctx).WithError(err).Debug("could not evaluate native pipeline cache, rebuilding")
	} else if ok {
		return cached, nil
	}

	if err := os.RemoveAll(stageDir); err != nil {
		return nil, fmt.Errorf("clearing native build dir: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(rootfsDir, "app"), 0o755); err != nil {
		return nil, fmt.Errorf("creating rootfs dir: %w", err)
	}

	if err := enforceDeterministicBuildRequirements(opts, opts.Workdir, pack.Name()); err != nil {
		return nil, err
	}

	buildStarted := time.Now()
	log.G(ctx).WithField("language_pack", pack.Name()).Info("starting native build step")
	buildResult, err := pack.Build(ctx, opts, opts.Workdir, rootfsDir, cfg)
	if err != nil {
		return nil, err
	}
	log.G(ctx).WithFields(map[string]interface{}{
		"language_pack": pack.Name(),
		"elapsed":       time.Since(buildStarted).Round(time.Second).String(),
	}).Info("native build step completed")

	runtimeName := runtimeutil.Normalize(firstNonEmpty(cfg.Runtime, buildResult.Runtime, runtimeutil.DefaultRuntime), "latest")
	if runtimeName == "" {
		runtimeName = runtimeutil.DefaultRuntime
	}
	command := buildResult.Command
	if len(cfg.Run.Command) > 0 {
		command = cfg.Run.Command
	}
	if len(command) == 0 {
		command = []string{"/app/app"}
	}

	if err := writeGeneratedKraftfile(kraftfilePath, runtimeName, command); err != nil {
		return nil, err
	}

	if err := writeNativePackMetadata(filepath.Join(stageDir, "pack-metadata.json"), nativePackMetadata{
		LayoutVersion:  nativePipelineLayoutVersion,
		LanguagePack:   pack.Name(),
		BuildMode:      buildMode(opts),
		Runtime:        runtimeName,
		Command:        command,
		RootfsDir:      rootfsDir,
		Deterministic:  !isDebugBuild(opts),
		GeneratedAtUTC: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"language_pack": pack.Name(),
		"runtime":       runtimeName,
		"rootfs":        rootfsDir,
	}).Info("prepared native source pipeline")

	return &nativePipelineResult{
		RootfsDir: rootfsDir,
		Kraftfile: kraftfilePath,
		Runtime:   runtimeName,
		Command:   command,
		Pack:      pack.Name(),
	}, nil
}

func loadNativeProjectConfig(workdir string) (*nativeProjectConfig, error) {
	cfg := &nativeProjectConfig{}
	path := filepath.Join(workdir, "unik.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading unik.yaml: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing unik.yaml: %w", err)
	}

	return cfg, nil
}

func selectNativePack(workdir string, cfg *nativeProjectConfig) (nativeLanguagePack, error) {
	packs := []nativeLanguagePack{
		&goPack{},
		&rustPack{},
		&nodePack{},
		&pythonPack{},
		&javaPack{},
		&dotnetPack{},
	}

	if cfg.Build.Command != "" {
		return &customPack{}, nil
	}

	if cfg.Language != "" {
		for _, pack := range packs {
			if matchesLanguage(pack.Name(), cfg.Language) {
				return pack, nil
			}
		}

		return nil, fmt.Errorf("unsupported language in unik.yaml: %s (supported: go, rust, node, python, java, dotnet)", cfg.Language)
	}

	for _, pack := range packs {
		if pack.Detect(workdir) {
			return pack, nil
		}
	}

	return nil, fmt.Errorf("could not detect language pack; add unik.yaml with build.command for custom pipeline")
}

type goPack struct{}

func (*goPack) Name() string { return "go" }

func (*goPack) Detect(workdir string) bool {
	return fileExists(filepath.Join(workdir, "go.mod"))
}

func (*goPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, _ *nativeProjectConfig) (*nativeBuildResult, error) {
	output := filepath.Join(rootfsDir, "app", "app")
	env := map[string]string{
		"GOOS":         "linux",
		"GOARCH":       normalizeGoArch(opts.Architecture),
		"CGO_ENABLED":  "0",
	}

	args := []string{"build", "-trimpath"}
	args = append(args, "-buildmode=pie")
	if isDebugBuild(opts) {
		args = append(args, "-gcflags", "all=-N -l")
	} else {
		args = append(args, "-ldflags", "-s -w")
	}
	args = append(args, "-o", output, ".")

	if err := runCommand(ctx, opts, workdir, env, "go", args...); err != nil {
		return nil, err
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.DefaultRuntime,
		Command: []string{"/app/app"},
	}, nil
}

type rustPack struct{}

func (*rustPack) Name() string { return "rust" }

func (*rustPack) Detect(workdir string) bool {
	return fileExists(filepath.Join(workdir, "Cargo.toml"))
}

func (*rustPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, _ *nativeProjectConfig) (*nativeBuildResult, error) {
	target := normalizeRustTarget(opts.Architecture)
	profile := "release"

	args := []string{"build", "--target", target}
	if !isDebugBuild(opts) {
		args = append(args, "--release")
	} else {
		profile = "debug"
	}

	if err := runCommand(ctx, opts, workdir, nil, "cargo", args...); err != nil {
		return nil, err
	}

	artifactDir := filepath.Join(workdir, "target", target, profile)
	artifact, err := findRustArtifact(artifactDir)
	if err != nil {
		return nil, err
	}

	if err := copyFile(artifact, filepath.Join(rootfsDir, "app", "app")); err != nil {
		return nil, fmt.Errorf("copying rust artifact: %w", err)
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.DefaultRuntime,
		Command: []string{"/app/app"},
	}, nil
}

type nodePack struct{}

func (*nodePack) Name() string { return "node" }

func (*nodePack) Detect(workdir string) bool {
	return fileExists(filepath.Join(workdir, "package.json"))
}

func (*nodePack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, _ *nativeProjectConfig) (*nativeBuildResult, error) {
	buildDir := filepath.Join(filepath.Dir(rootfsDir), "node-build")
	if err := os.RemoveAll(buildDir); err != nil {
		return nil, fmt.Errorf("clearing node build dir: %w", err)
	}
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating node build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	if err := copyDir(workdir, buildDir, map[string]struct{}{
		".git":         {},
		".unikctl":     {},
		".unikraft":    {},
		"node_modules": {},
		"dist":         {},
		"build":        {},
		"out":          {},
	}); err != nil {
		return nil, fmt.Errorf("copying source tree: %w", err)
	}

	manifest, err := readNodeManifest(filepath.Join(buildDir, "package.json"))
	if err != nil {
		return nil, err
	}

	hasBuildScript := strings.TrimSpace(manifest.Scripts["build"]) != ""
	npmArgs := nodeInstallArgs(buildDir, hasBuildScript, isDebugBuild(opts))

	if err := runCommand(ctx, opts, buildDir, nil, "npm", npmArgs...); err != nil {
		return nil, err
	}

	if hasBuildScript {
		if err := runCommand(ctx, opts, buildDir, nil, "npm", "run", "build"); err != nil {
			return nil, err
		}

		if staticDir, ok := detectNodeStaticOutput(buildDir, manifest); ok {
			wwwDir := filepath.Join(rootfsDir, "app", "www")
			if err := os.MkdirAll(wwwDir, 0o755); err != nil {
				return nil, fmt.Errorf("creating static output dir: %w", err)
			}
			if err := copyDir(staticDir, wwwDir, map[string]struct{}{}); err != nil {
				return nil, fmt.Errorf("copying static build output: %w", err)
			}

			serverBin := filepath.Join(rootfsDir, "app", "app")
			if err := buildStaticHTTPServerBinary(ctx, opts, serverBin); err != nil {
				return nil, err
			}

			return &nativeBuildResult{
				Runtime: runtimeutil.DefaultRuntime,
				Command: []string{"/app/app", "--dir", "/app/www", "--addr", ":8080"},
			}, nil
		}
	}

	appDir := filepath.Join(rootfsDir, "app")
	if err := os.RemoveAll(appDir); err != nil {
		return nil, fmt.Errorf("clearing node app dir: %w", err)
	}
	if err := copyDir(buildDir, appDir, map[string]struct{}{
		".git":      {},
		".unikctl":  {},
		".unikraft": {},
		"dist":      {},
		"build":     {},
		"out":       {},
	}); err != nil {
		return nil, fmt.Errorf("copying node app runtime tree: %w", err)
	}

	mainEntry := manifest.Main
	if strings.TrimSpace(mainEntry) == "" {
		mainEntry = "index.js"
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.RuntimeRegistryPrefix + "/nodejs:latest",
		Command: []string{"node", "/app/" + filepath.ToSlash(mainEntry)},
	}, nil
}

type pythonPack struct{}

func (*pythonPack) Name() string { return "python" }

func (*pythonPack) Detect(workdir string) bool {
	if fileExists(filepath.Join(workdir, "requirements.txt")) || fileExists(filepath.Join(workdir, "pyproject.toml")) {
		return true
	}

	pyFiles, _ := filepath.Glob(filepath.Join(workdir, "*.py"))
	if len(pyFiles) > 0 {
		return true
	}

	return hasPythonSourceFiles(workdir)
}

func (*pythonPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, cfg *nativeProjectConfig) (*nativeBuildResult, error) {
	appDir := filepath.Join(rootfsDir, "app")
	if err := copyDir(workdir, appDir, map[string]struct{}{
		".git":         {},
		".unikctl":     {},
		".unikraft":    {},
		".venv":        {},
		"venv":         {},
		"__pycache__":  {},
		"node_modules": {},
		"target":       {},
		"bin":          {},
		"obj":          {},
	}); err != nil {
		return nil, fmt.Errorf("copying source tree: %w", err)
	}

	pythonCommand, err := detectPythonCommand(appDir)
	if err != nil {
		return nil, err
	}

	requirements := filepath.Join(workdir, "requirements.txt")
	if fileExists(requirements) {
		if err := runCommand(ctx, opts, workdir, nil, "pip", "install", "-r", requirements, "--target", appDir); err != nil {
			return nil, err
		}
	} else if fileExists(filepath.Join(workdir, "pyproject.toml")) {
		if err := runCommand(ctx, opts, workdir, nil, "pip", "install", ".", "--target", appDir); err != nil {
			return nil, err
		}
	}

	if len(cfg.Run.Command) > 0 {
		return &nativeBuildResult{
			Runtime: runtimeutil.RuntimeRegistryPrefix + "/python:latest",
			Command: cfg.Run.Command,
		}, nil
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.RuntimeRegistryPrefix + "/python:latest",
		Command: pythonCommand,
	}, nil
}

type javaPack struct{}

func (*javaPack) Name() string { return "java" }

func (*javaPack) Detect(workdir string) bool {
	return fileExists(filepath.Join(workdir, "pom.xml")) ||
		fileExists(filepath.Join(workdir, "build.gradle")) ||
		fileExists(filepath.Join(workdir, "build.gradle.kts"))
}

func (*javaPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, _ *nativeProjectConfig) (*nativeBuildResult, error) {
	switch {
	case fileExists(filepath.Join(workdir, "pom.xml")):
		if err := runCommand(ctx, opts, workdir, nil, "mvn", "-DskipTests", "package"); err != nil {
			return nil, err
		}
	case fileExists(filepath.Join(workdir, "gradlew")) || fileExists(filepath.Join(workdir, "gradlew.bat")):
		gradle := "gradle"
		if runtime.GOOS == "windows" && fileExists(filepath.Join(workdir, "gradlew.bat")) {
			gradle = "gradlew.bat"
		} else if fileExists(filepath.Join(workdir, "gradlew")) {
			gradle = filepath.Join(".", "gradlew")
		}
		if err := runCommand(ctx, opts, workdir, nil, gradle, "build"); err != nil {
			return nil, err
		}
	default:
		if err := runCommand(ctx, opts, workdir, nil, "gradle", "build"); err != nil {
			return nil, err
		}
	}

	artifact, err := findJavaArtifact(workdir)
	if err != nil {
		return nil, err
	}

	dst := filepath.Join(rootfsDir, "app", "app.jar")
	if err := copyFile(artifact, dst); err != nil {
		return nil, fmt.Errorf("copying java artifact: %w", err)
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.RuntimeRegistryPrefix + "/java:latest",
		Command: []string{"java", "-jar", "/app/app.jar"},
	}, nil
}

type dotnetPack struct{}

func (*dotnetPack) Name() string { return "dotnet" }

func (*dotnetPack) Detect(workdir string) bool {
	csproj, _ := filepath.Glob(filepath.Join(workdir, "*.csproj"))
	sln, _ := filepath.Glob(filepath.Join(workdir, "*.sln"))
	return len(csproj) > 0 || len(sln) > 0
}

func (*dotnetPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, _ *nativeProjectConfig) (*nativeBuildResult, error) {
	publishDir := filepath.Join(filepath.Dir(rootfsDir), "dotnet-publish")
	if err := os.RemoveAll(publishDir); err != nil {
		return nil, fmt.Errorf("clearing dotnet publish dir: %w", err)
	}

	configMode := "Release"
	if isDebugBuild(opts) {
		configMode = "Debug"
	}

	if err := runCommand(ctx, opts, workdir, nil, "dotnet", "publish", "-c", configMode, "-o", publishDir); err != nil {
		return nil, err
	}

	dllName, err := detectDotnetEntryDLL(publishDir)
	if err != nil {
		return nil, err
	}

	if err := copyDir(publishDir, filepath.Join(rootfsDir, "app"), map[string]struct{}{}); err != nil {
		return nil, fmt.Errorf("copying dotnet publish output: %w", err)
	}

	return &nativeBuildResult{
		Runtime: runtimeutil.RuntimeRegistryPrefix + "/dotnet:latest",
		Command: []string{"dotnet", "/app/" + dllName},
	}, nil
}

type customPack struct{}

func (*customPack) Name() string { return "custom" }

func (*customPack) Detect(_ string) bool { return false }

func (*customPack) Build(ctx context.Context, opts *BuildOptions, workdir, rootfsDir string, cfg *nativeProjectConfig) (*nativeBuildResult, error) {
	if cfg.Build.Command == "" {
		return nil, fmt.Errorf("custom pack requires unik.yaml build.command")
	}

	if err := runShellCommand(ctx, opts, workdir, cfg.Build.Command, map[string]string{
		"UNIKCTL_BUILD_MODE": buildMode(opts),
	}); err != nil {
		return nil, err
	}

	if cfg.Artifact.Path == "" {
		return nil, fmt.Errorf("custom pack requires unik.yaml artifact.path")
	}

	src := cfg.Artifact.Path
	if !filepath.IsAbs(src) {
		src = filepath.Join(workdir, src)
	}

	dst := filepath.Join(rootfsDir, "app", "app")
	info, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("invalid artifact.path: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(src, filepath.Join(rootfsDir, "app"), map[string]struct{}{}); err != nil {
			return nil, fmt.Errorf("copying artifact dir: %w", err)
		}
	} else if err := copyFile(src, dst); err != nil {
		return nil, fmt.Errorf("copying artifact file: %w", err)
	}

	cmd := cfg.Run.Command
	if len(cmd) == 0 {
		cmd = []string{"/app/app"}
	}

	runtimeName := runtimeutil.Normalize(firstNonEmpty(cfg.Runtime, runtimeutil.RuntimeRegistryPrefix+"/base"), "latest")
	if runtimeName == "" {
		runtimeName = runtimeutil.DefaultRuntime
	}

	return &nativeBuildResult{
		Runtime: runtimeName,
		Command: cmd,
	}, nil
}

func writeGeneratedKraftfile(path, runtimeName string, cmd []string) error {
	data, err := yaml.Marshal(generatedKraftfile{
		Spec:    "v0.6",
		Runtime: runtimeName,
		Cmd:     cmd,
	})
	if err != nil {
		return fmt.Errorf("marshalling generated Kraftfile: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating generated Kraftfile dir: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing generated Kraftfile: %w", err)
	}

	return nil
}

func runCommand(ctx context.Context, opts *BuildOptions, dir string, env map[string]string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()

	for k, v := range toolCacheEnv(opts, name) {
		cmd.Env = upsertEnv(cmd.Env, k, v)
	}

	for k, v := range env {
		cmd.Env = upsertEnv(cmd.Env, k, v)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe for %s: %w", name, err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("creating stderr pipe for %s: %w", name, err)
	}

	commandLabel := strings.TrimSpace(strings.Join(append([]string{name}, args...), " "))
	log.G(ctx).WithFields(map[string]interface{}{
		"command": commandLabel,
		"cwd":     dir,
	}).Info("running")

	var output bytes.Buffer
	var outputMu sync.Mutex

	lastOutput := atomic.Int64{}
	lastOutput.Store(time.Now().UnixNano())
	started := time.Now()

	appendLine := func(line string) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return
		}

		now := time.Now().UnixNano()
		lastOutput.Store(now)

		outputMu.Lock()
		output.WriteString(line)
		output.WriteByte('\n')
		outputMu.Unlock()

		log.G(ctx).Infof("  [%s] %s", filepath.Base(name), line)
	}

	streamPipe := func(reader io.ReadCloser) error {
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			appendLine(scanner.Text())
		}

		return scanner.Err()
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command failed: %s: %w", commandLabel, err)
	}

	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				last := time.Unix(0, lastOutput.Load())
				if time.Since(last) >= 15*time.Second {
					log.G(ctx).WithFields(map[string]interface{}{
						"command": commandLabel,
						"elapsed": time.Since(started).Round(time.Second).String(),
					}).Info("still running")
				}
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	var streamErr error
	var streamErrMu sync.Mutex
	recordStreamErr := func(err error) {
		if err == nil {
			return
		}
		streamErrMu.Lock()
		defer streamErrMu.Unlock()
		if streamErr == nil {
			streamErr = err
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		recordStreamErr(streamPipe(stdoutPipe))
	}()
	go func() {
		defer wg.Done()
		recordStreamErr(streamPipe(stderrPipe))
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	outputBytes := output.Bytes()
	if len(outputBytes) > 0 {
		if werr := appendBuildLog(opts.SaveBuildLog, outputBytes); werr != nil {
			return werr
		}
	}

	if streamErr != nil {
		return fmt.Errorf("reading command output failed: %s: %w", commandLabel, streamErr)
	}

	if waitErr != nil {
		return fmt.Errorf("command failed: %s: %w\n%s", commandLabel, waitErr, string(outputBytes))
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"command": commandLabel,
		"elapsed": time.Since(started).Round(time.Second).String(),
	}).Info("completed")

	return nil
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	entry := prefix + value
	for i, current := range env {
		if strings.HasPrefix(current, prefix) {
			env[i] = entry
			return env
		}
	}

	return append(env, entry)
}

func runShellCommand(ctx context.Context, opts *BuildOptions, dir, script string, env map[string]string) error {
	if runtime.GOOS == "windows" {
		return runCommand(ctx, opts, dir, env, "cmd", "/C", script)
	}

	return runCommand(ctx, opts, dir, env, "sh", "-c", script)
}

func appendBuildLog(path string, data []byte) error {
	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("opening build log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing build log: %w", err)
	}

	return nil
}

func toolCacheEnv(opts *BuildOptions, tool string) map[string]string {
	if opts == nil || strings.TrimSpace(opts.Workdir) == "" {
		return map[string]string{}
	}

	workdir, err := filepath.Abs(opts.Workdir)
	if err != nil {
		return map[string]string{}
	}

	cacheRoot := filepath.Join(workdir, ".unikctl", "cache")
	tool = strings.ToLower(strings.TrimSpace(tool))

	switch tool {
	case "npm":
		return map[string]string{
			"NPM_CONFIG_CACHE": filepath.Join(cacheRoot, "npm"),
		}
	case "pip":
		return map[string]string{
			"PIP_CACHE_DIR": filepath.Join(cacheRoot, "pip"),
		}
	case "cargo":
		return map[string]string{
			"CARGO_HOME":       filepath.Join(cacheRoot, "cargo", "home"),
			"CARGO_TARGET_DIR": filepath.Join(cacheRoot, "cargo", "target"),
		}
	case "go":
		return map[string]string{
			"GOCACHE":    filepath.Join(cacheRoot, "go-build"),
			"GOMODCACHE": filepath.Join(cacheRoot, "go-mod"),
		}
	default:
		return map[string]string{}
	}
}

func enforceDeterministicBuildRequirements(opts *BuildOptions, workdir, packName string) error {
	if isDebugBuild(opts) {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(packName)) {
	case "node":
		if fileExists(filepath.Join(workdir, "package-lock.json")) || fileExists(filepath.Join(workdir, "npm-shrinkwrap.json")) || fileExists(filepath.Join(workdir, "yarn.lock")) || fileExists(filepath.Join(workdir, "pnpm-lock.yaml")) {
			return nil
		}
		return fmt.Errorf("release mode requires a lockfile for node projects (package-lock.json, npm-shrinkwrap.json, yarn.lock, or pnpm-lock.yaml)")
	case "python":
		if fileExists(filepath.Join(workdir, "requirements.txt")) || fileExists(filepath.Join(workdir, "poetry.lock")) || fileExists(filepath.Join(workdir, "uv.lock")) {
			return nil
		}
		return fmt.Errorf("release mode requires dependency lock input for python projects (requirements.txt, poetry.lock, or uv.lock)")
	case "rust":
		if fileExists(filepath.Join(workdir, "Cargo.lock")) {
			return nil
		}
		return fmt.Errorf("release mode requires Cargo.lock for deterministic rust builds")
	case "go":
		if fileExists(filepath.Join(workdir, "go.sum")) {
			return nil
		}
		return fmt.Errorf("release mode requires go.sum for deterministic go builds")
	default:
		return nil
	}
}

func writeNativePackMetadata(path string, metadata nativePackMetadata) error {
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing native pack metadata: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating metadata directory: %w", err)
	}

	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("writing native pack metadata: %w", err)
	}

	return nil
}

func copyDir(src, dst string, skip map[string]struct{}) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		name := d.Name()
		if _, ok := skip[name]; ok {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		dstPath := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}

		return copyFile(path, dstPath)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return nil
}

func readNodeMain(path string) (string, error) {
	type nodeManifest struct {
		Main string `json:"main"`
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading package.json: %w", err)
	}

	m := nodeManifest{}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parsing package.json: %w", err)
	}

	if m.Main == "" {
		return "index.js", nil
	}

	return m.Main, nil
}

func readNodeManifest(path string) (*nodePackageManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	m := &nodePackageManifest{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	return m, nil
}

func nodeInstallArgs(appDir string, includeDevDependencies, debug bool) []string {
	hasLock := fileExists(filepath.Join(appDir, "package-lock.json"))
	if hasLock {
		if includeDevDependencies || debug {
			return []string{"ci"}
		}
		return []string{"ci", "--omit=dev"}
	}

	if includeDevDependencies || debug {
		return []string{"install"}
	}

	return []string{"install", "--omit=dev"}
}

func detectNodeStaticOutput(appDir string, manifest *nodePackageManifest) (string, bool) {
	candidates := []string{}
	if manifest != nil {
		if custom := strings.TrimSpace(manifest.Unikctl.Dist); custom != "" {
			candidates = append(candidates, custom)
		}
	}

	candidates = append(candidates, "dist", "build", "out")
	for _, candidate := range candidates {
		path := candidate
		if !filepath.IsAbs(path) {
			path = filepath.Join(appDir, candidate)
		}

		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}

		return path, true
	}

	return "", false
}

func buildStaticHTTPServerBinary(ctx context.Context, opts *BuildOptions, outputPath string) error {
	sourceDir := filepath.Join(filepath.Dir(outputPath), ".unikctl-static-server")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return fmt.Errorf("creating static server build dir: %w", err)
	}
	defer os.RemoveAll(sourceDir)

	mainFile := filepath.Join(sourceDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(staticHTTPServerSource), 0o644); err != nil {
		return fmt.Errorf("writing static server source: %w", err)
	}

	goarch := normalizeGoArch(opts.Architecture)
	env := map[string]string{
		"GOOS":         "linux",
		"GOARCH":       goarch,
		"CGO_ENABLED":  "0",
	}

	args := []string{"build", "-trimpath"}
	args = append(args, "-buildmode=pie")
	if isDebugBuild(opts) {
		args = append(args, "-gcflags", "all=-N -l")
	} else {
		args = append(args, "-ldflags", "-s -w")
	}
	args = append(args, "-o", outputPath, "main.go")

	if err := runCommand(ctx, opts, sourceDir, env, "go", args...); err != nil {
		return fmt.Errorf("building static HTTP server binary: %w", err)
	}

	return nil
}

const staticHTTPServerSource = `package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	dir := flag.String("dir", "/app/www", "directory to serve")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	log.Printf("serving %s on %s", *dir, *addr)
	if err := http.ListenAndServe(*addr, http.FileServer(http.Dir(*dir))); err != nil {
		log.Fatal(err)
	}
}
`

func findRustArtifact(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("reading rust release dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".d") || strings.HasSuffix(name, ".rlib") || strings.HasSuffix(name, ".rmeta") || strings.HasSuffix(name, ".pdb") {
			continue
		}

		return filepath.Join(dir, name), nil
	}

	return "", fmt.Errorf("could not determine rust release artifact in %s", dir)
}

func findJavaArtifact(workdir string) (string, error) {
	candidates := []string{}
	collectJars := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".jar") {
				continue
			}
			lower := strings.ToLower(name)
			if strings.Contains(lower, "sources") || strings.Contains(lower, "javadoc") || strings.Contains(lower, "original") || strings.Contains(lower, "plain") {
				continue
			}
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}

	collectJars(filepath.Join(workdir, "target"))
	collectJars(filepath.Join(workdir, "build", "libs"))

	if len(candidates) == 0 {
		return "", fmt.Errorf("could not find java artifact in target/ or build/libs/")
	}

	return candidates[0], nil
}

func detectPythonCommand(appDir string) ([]string, error) {
	for _, candidate := range []string{"main.py", "app.py", "__main__.py", "index.py", "manage.py", "server.py"} {
		if fileExists(filepath.Join(appDir, candidate)) {
			return []string{"python", "/app/" + filepath.ToSlash(candidate)}, nil
		}
	}

	if module, ok := detectPythonMainModule(appDir); ok {
		return []string{"python", "-m", module}, nil
	}

	if launcher, ok := detectPythonPyprojectScript(appDir); ok {
		return []string{"python", "/app/" + filepath.ToSlash(launcher)}, nil
	}

	if entry, ok := detectPythonFileFallback(appDir); ok {
		return []string{"python", "/app/" + filepath.ToSlash(entry)}, nil
	}

	return nil, fmt.Errorf("could not detect python entrypoint; add run.command in unik.yaml")
}

func detectPythonMainModule(appDir string) (string, bool) {
	candidates := []string{}

	_ = filepath.WalkDir(appDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() && shouldSkipPythonSearchDir(entry.Name()) {
			return fs.SkipDir
		}
		if entry.IsDir() || strings.ToLower(entry.Name()) != "__main__.py" {
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})

	if len(candidates) == 0 {
		return "", false
	}

	sort.Strings(candidates)
	for _, path := range candidates {
		rel, err := filepath.Rel(appDir, filepath.Dir(path))
		if err != nil {
			continue
		}

		rel = filepath.ToSlash(rel)
		if rel == "." || rel == "" {
			return "__main__", true
		}

		if strings.HasPrefix(rel, "src/") {
			rel = strings.TrimPrefix(rel, "src/")
		}

		module := strings.ReplaceAll(rel, "/", ".")
		module = strings.Trim(module, ".")
		if module != "" {
			return module, true
		}
	}

	return "", false
}

func detectPythonPyprojectScript(appDir string) (string, bool) {
	pyprojectPath := filepath.Join(appDir, "pyproject.toml")
	if !fileExists(pyprojectPath) {
		return "", false
	}

	raw, err := os.ReadFile(pyprojectPath)
	if err != nil {
		return "", false
	}

	manifest := pyprojectManifest{}
	if err := toml.Unmarshal(raw, &manifest); err != nil {
		return "", false
	}

	scripts := map[string]string{}
	for name, target := range manifest.Project.Scripts {
		scripts[name] = target
	}
	for name, target := range manifest.Tool.Poetry.Scripts {
		if _, exists := scripts[name]; !exists {
			scripts[name] = target
		}
	}

	if len(scripts) == 0 {
		return "", false
	}

	names := make([]string, 0, len(scripts))
	for name := range scripts {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		module, function, ok := splitPythonScriptTarget(scripts[name])
		if !ok {
			continue
		}

		launcherPath, err := writePythonScriptLauncher(appDir, module, function)
		if err != nil {
			continue
		}

		return launcherPath, true
	}

	return "", false
}

func splitPythonScriptTarget(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n\"'`") {
		return "", "", false
	}

	module, function, ok := strings.Cut(value, ":")
	if !ok {
		return "", "", false
	}

	module = strings.TrimSpace(module)
	function = strings.TrimSpace(function)
	if module == "" || function == "" {
		return "", "", false
	}

	return module, function, true
}

func writePythonScriptLauncher(appDir, module, function string) (string, error) {
	launcherName := ".unikctl_entrypoint.py"
	launcherPath := filepath.Join(appDir, launcherName)
	content := fmt.Sprintf("from %s import %s\n\nif __name__ == '__main__':\n    raise SystemExit(%s())\n", module, function, function)

	if err := os.WriteFile(launcherPath, []byte(content), 0o644); err != nil {
		return "", err
	}

	return launcherName, nil
}

func detectPythonFileFallback(appDir string) (string, bool) {
	rootCandidates := []string{}
	rootFiles, _ := filepath.Glob(filepath.Join(appDir, "*.py"))
	for _, path := range rootFiles {
		rootCandidates = append(rootCandidates, filepath.Base(path))
	}
	sort.Strings(rootCandidates)
	if len(rootCandidates) == 1 {
		return rootCandidates[0], true
	}
	for _, preferred := range []string{"main.py", "app.py", "server.py", "manage.py"} {
		for _, candidate := range rootCandidates {
			if candidate == preferred {
				return candidate, true
			}
		}
	}

	recursive := []string{}
	_ = filepath.WalkDir(appDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if entry.IsDir() && shouldSkipPythonSearchDir(entry.Name()) {
			return fs.SkipDir
		}

		if entry.IsDir() || filepath.Ext(strings.ToLower(entry.Name())) != ".py" {
			return nil
		}

		rel, err := filepath.Rel(appDir, path)
		if err != nil {
			return nil
		}
		recursive = append(recursive, rel)
		return nil
	})

	if len(recursive) == 0 {
		return "", false
	}

	sort.SliceStable(recursive, func(i, j int) bool {
		di := strings.Count(filepath.ToSlash(recursive[i]), "/")
		dj := strings.Count(filepath.ToSlash(recursive[j]), "/")
		if di != dj {
			return di < dj
		}
		return recursive[i] < recursive[j]
	})

	return recursive[0], true
}

func shouldSkipPythonSearchDir(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ".git", ".venv", "venv", "__pycache__", "node_modules", "site-packages", "dist", "build", ".unikctl":
		return true
	default:
		return false
	}
}

func hasPythonSourceFiles(workdir string) bool {
	found := false
	_ = filepath.WalkDir(workdir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || found {
			return nil
		}

		if entry.IsDir() && shouldSkipPythonSearchDir(entry.Name()) {
			return fs.SkipDir
		}

		if entry.IsDir() {
			return nil
		}

		if strings.EqualFold(filepath.Ext(entry.Name()), ".py") {
			found = true
			return io.EOF
		}

		return nil
	})

	return found
}

func detectDotnetEntryDLL(publishDir string) (string, error) {
	runtimeConfigs, _ := filepath.Glob(filepath.Join(publishDir, "*.runtimeconfig.json"))
	for _, cfg := range runtimeConfigs {
		base := strings.TrimSuffix(filepath.Base(cfg), ".runtimeconfig.json")
		dll := base + ".dll"
		if fileExists(filepath.Join(publishDir, dll)) {
			return dll, nil
		}
	}

	dlls, _ := filepath.Glob(filepath.Join(publishDir, "*.dll"))
	for _, dllPath := range dlls {
		name := strings.ToLower(filepath.Base(dllPath))
		if strings.Contains(name, "testhost") || strings.HasSuffix(name, ".resources.dll") {
			continue
		}
		return filepath.Base(dllPath), nil
	}

	return "", fmt.Errorf("could not detect dotnet entrypoint dll in %s", publishDir)
}

func matchesLanguage(packName, value string) bool {
	packName = strings.ToLower(strings.TrimSpace(packName))
	value = strings.ToLower(strings.TrimSpace(value))

	if packName == value {
		return true
	}

	aliases := map[string][]string{
		"node":   {"nodejs", "javascript", "js"},
		"python": {"py"},
		"dotnet": {"csharp", "cs", "net"},
	}

	for canonical, names := range aliases {
		if packName != canonical {
			continue
		}
		for _, alias := range names {
			if value == alias {
				return true
			}
		}
	}

	return false
}

func normalizeGoArch(arch string) string {
	switch arch {
	case "x86_64", "amd64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	case "arm":
		return "arm"
	default:
		return "amd64"
	}
}

func normalizeRustTarget(arch string) string {
	switch arch {
	case "arm64", "aarch64":
		return "aarch64-unknown-linux-musl"
	case "arm":
		return "armv7-unknown-linux-musleabihf"
	default:
		return "x86_64-unknown-linux-musl"
	}
}

func isDebugBuild(opts *BuildOptions) bool {
	if opts == nil {
		return false
	}

	return opts.Debug || opts.KernelDbg
}

func buildMode(opts *BuildOptions) string {
	if isDebugBuild(opts) {
		return "debug"
	}

	return "release"
}

func tryReuseNativePipeline(ctx context.Context, workdir, stageDir, packName, mode string) (*nativePipelineResult, bool, error) {
	metadataPath := filepath.Join(stageDir, "pack-metadata.json")
	kraftfilePath := filepath.Join(stageDir, "Kraftfile")

	if !fileExists(metadataPath) || !fileExists(kraftfilePath) {
		return nil, false, nil
	}

	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, false, fmt.Errorf("reading cached metadata: %w", err)
	}

	metadata := nativePackMetadata{}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, false, fmt.Errorf("parsing cached metadata: %w", err)
	}

	if strings.TrimSpace(metadata.LanguagePack) != strings.TrimSpace(packName) ||
		strings.TrimSpace(metadata.BuildMode) != strings.TrimSpace(mode) {
		return nil, false, nil
	}
	if metadata.LayoutVersion != nativePipelineLayoutVersion {
		return nil, false, nil
	}

	rootfsDir := strings.TrimSpace(metadata.RootfsDir)
	if rootfsDir == "" {
		rootfsDir = filepath.Join(stageDir, "rootfs")
	}
	if !filepath.IsAbs(rootfsDir) {
		rootfsDir = filepath.Join(workdir, rootfsDir)
	}
	rootfsDir = filepath.Clean(rootfsDir)

	rootfsInfo, err := os.Stat(rootfsDir)
	if err != nil || !rootfsInfo.IsDir() {
		return nil, false, nil
	}

	latestSourceMod, err := latestSourceModTime(workdir)
	if err != nil {
		return nil, false, err
	}

	if !metadata.GeneratedAtUTC.IsZero() && latestSourceMod.After(metadata.GeneratedAtUTC) {
		return nil, false, nil
	}

	if metadata.Runtime == "" {
		metadata.Runtime = runtimeutil.DefaultRuntime
	}
	if len(metadata.Command) == 0 {
		metadata.Command = []string{"/app/app"}
	}

	log.G(ctx).WithFields(map[string]interface{}{
		"language_pack": metadata.LanguagePack,
		"mode":          metadata.BuildMode,
		"rootfs":        rootfsDir,
	}).Info("reusing cached native source pipeline")

	return &nativePipelineResult{
		RootfsDir: rootfsDir,
		Kraftfile: kraftfilePath,
		Runtime:   metadata.Runtime,
		Command:   metadata.Command,
		Pack:      metadata.LanguagePack,
	}, true, nil
}

func latestSourceModTime(workdir string) (time.Time, error) {
	latest := time.Time{}

	skipDirs := map[string]struct{}{
		".git":         {},
		".unikctl":     {},
		".unikraft":    {},
		"node_modules": {},
		"target":       {},
		"bin":          {},
		"obj":          {},
		".venv":        {},
		"venv":         {},
		"__pycache__":  {},
		"dist":         {},
		"build":        {},
		"out":          {},
	}

	err := filepath.WalkDir(workdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == workdir {
			return nil
		}

		name := d.Name()
		if d.IsDir() {
			if _, ok := skipDirs[name]; ok {
				return fs.SkipDir
			}
			return nil
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
		return time.Time{}, fmt.Errorf("walking source tree: %w", err)
	}

	return latest.UTC(), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func isDockerfilePath(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}

	return strings.Contains(strings.ToLower(path), "dockerfile")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
