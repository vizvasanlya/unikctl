package run

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/nerdctl/v2/pkg/strutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	machineapi "unikctl.sh/api/machine/v1alpha1"
	networkapi "unikctl.sh/api/network/v1alpha1"
	volumeapi "unikctl.sh/api/volume/v1alpha1"
	"unikctl.sh/config"
	"unikctl.sh/initrd"
	"unikctl.sh/internal/cli/unikctl/utils"
	"unikctl.sh/log"
	machinename "unikctl.sh/machine/name"
	"unikctl.sh/machine/network"
	"unikctl.sh/machine/volume"
	"unikctl.sh/tui/processtree"
	"unikctl.sh/unikraft"
	"unikctl.sh/unikraft/app"
)

// Are we publishing ports? E.g. -p/--ports=127.0.0.1:80:8080/tcp ...
func (opts *RunOptions) assignPorts(ctx context.Context, machine *machineapi.Machine) error {
	autoAssigned := false
	if len(opts.Ports) == 0 {
		opts.Ports = inferAutoPublishPorts(machine)
		autoAssigned = len(opts.Ports) > 0
	}

	if len(opts.Ports) == 0 {
		return nil
	}

	opts.Ports = strutil.DedupeStrSlice(opts.Ports)
	for _, port := range opts.Ports {
		parsed, err := machineapi.ParsePort(port)
		if err != nil {
			return err
		}
		machine.Spec.Ports = append(machine.Spec.Ports, parsed...)
	}

	if autoAssigned {
		log.G(ctx).WithField("ports", strings.Join(opts.Ports, ",")).Info("auto-published detected service port")
	}

	return utils.CheckPorts(ctx, opts.machineController, machine)
}

func inferAutoPublishPorts(machine *machineapi.Machine) []string {
	if machine == nil {
		return nil
	}
	if len(machine.Spec.Ports) > 0 {
		return nil
	}

	ports := detectServicePortsFromArgs(machine.Spec.ApplicationArgs)
	if len(ports) == 0 {
		if fallbackPort, ok := inferDefaultServicePort(machine.Spec.ApplicationArgs); ok {
			ports = append(ports, fallbackPort)
		}
	}
	if len(ports) == 0 && looksLikeStaticHTTPServer(machine.Spec.ApplicationArgs) {
		ports = append(ports, 8080)
	}

	seen := map[int]struct{}{}
	mappings := []string{}
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		mappings = append(mappings, fmt.Sprintf("127.0.0.1:%d:%d/tcp", port, port))
	}

	return mappings
}

func detectServicePortsFromArgs(args []string) []int {
	ports := []int{}

	for i := 0; i < len(args); i++ {
		current := strings.TrimSpace(args[i])
		if current == "" {
			continue
		}

		switch current {
		case "--addr", "-addr", "--listen", "-listen", "--port", "-p", "--bind", "-b", "--http", "--socket":
			if i+1 < len(args) {
				if port, ok := parsePotentialPort(args[i+1]); ok {
					ports = append(ports, port)
				}
			}
			continue
		case "runserver":
			if i+1 < len(args) {
				if port, ok := parsePotentialPort(args[i+1]); ok {
					ports = append(ports, port)
				}
			}
			continue
		}

		for _, prefix := range []string{"--addr=", "--listen=", "--port=", "--bind=", "-b=", "--http=", "--socket="} {
			if strings.HasPrefix(current, prefix) {
				if port, ok := parsePotentialPort(strings.TrimPrefix(current, prefix)); ok {
					ports = append(ports, port)
				}
				break
			}
		}

		// Handle compact forms like `-p8080` or `-b0.0.0.0:8000`.
		for _, prefix := range []string{"-p", "-b"} {
			if strings.HasPrefix(current, prefix) && len(current) > len(prefix) {
				if port, ok := parsePotentialPort(strings.TrimPrefix(current, prefix)); ok {
					ports = append(ports, port)
				}
				break
			}
		}
	}

	return ports
}

func inferDefaultServicePort(args []string) (int, bool) {
	hasToken := func(token string) bool {
		for _, arg := range args {
			if strings.EqualFold(strings.TrimSpace(arg), token) {
				return true
			}
		}
		return false
	}

	containsName := func(substring string) bool {
		for _, arg := range args {
			value := strings.ToLower(strings.TrimSpace(arg))
			if value == "" {
				continue
			}
			if strings.Contains(value, substring) {
				return true
			}
		}
		return false
	}

	// Common Python HTTP servers default to 8000 if no explicit port is provided.
	if hasToken("uvicorn") || hasToken("gunicorn") || hasToken("hypercorn") || hasToken("runserver") {
		return 8000, true
	}

	// Flask defaults to 5000 if no explicit port is provided.
	if hasToken("flask") {
		return 5000, true
	}

	// For python entry scripts (main.py/app.py/server.py), assume backend-style default.
	if (hasToken("python") || hasToken("python3")) &&
		(containsName("main.py") || containsName("app.py") || containsName("server.py") || containsName("manage.py")) {
		return 8000, true
	}

	return 0, false
}

func parsePotentialPort(value string) (int, bool) {
	value = strings.TrimSpace(strings.Trim(value, "\"'"))
	if value == "" {
		return 0, false
	}

	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = strings.TrimSpace(parsed.Host)
		}
	}

	if strings.HasPrefix(value, ":") {
		if port, err := strconv.Atoi(strings.TrimPrefix(value, ":")); err == nil {
			return port, true
		}
	}

	if host, portStr, err := net.SplitHostPort(value); err == nil {
		_ = host
		if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
			return port, true
		}
	}

	if port, err := strconv.Atoi(value); err == nil {
		return port, true
	}

	return 0, false
}

func looksLikeStaticHTTPServer(args []string) bool {
	hasAppBinary := false
	hasDirFlag := false
	hasStaticDir := false

	for _, arg := range args {
		value := strings.TrimSpace(arg)
		if value == "/app/app" {
			hasAppBinary = true
		}
		if value == "--dir" || strings.HasPrefix(value, "--dir=") {
			hasDirFlag = true
		}
		if value == "/app/www" || strings.Contains(value, "/app/www") {
			hasStaticDir = true
		}
	}

	return hasAppBinary && hasDirFlag && hasStaticDir
}

func launchURLFromMachinePorts(ports machineapi.MachinePorts, fallbackHost string) string {
	bestIndex := -1
	bestScore := 1 << 30

	for index, candidate := range ports {
		hostPort := int(candidate.HostPort)
		if hostPort <= 0 {
			continue
		}

		protocol := strings.ToLower(strings.TrimSpace(string(candidate.Protocol)))
		if protocol != "" && protocol != "tcp" {
			continue
		}

		score := hostPort + 1000
		switch hostPort {
		case 443:
			score = 0
		case 80:
			score = 1
		case 8080:
			score = 2
		case 3000:
			score = 3
		case 5173:
			score = 4
		case 5000:
			score = 5
		}

		if score < bestScore {
			bestScore = score
			bestIndex = index
		}
	}

	if bestIndex < 0 {
		return ""
	}

	selected := ports[bestIndex]
	host := normalizeLaunchHost(selected.HostIP, fallbackHost)
	if host == "" {
		host = "127.0.0.1"
	}

	hostPort := int(selected.HostPort)
	machinePort := int(selected.MachinePort)
	scheme := "http"
	if hostPort == 443 || machinePort == 443 {
		scheme = "https"
	}

	if (scheme == "http" && hostPort == 80) || (scheme == "https" && hostPort == 443) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, hostPort)
}

func normalizeLaunchHost(host, fallbackHost string) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = strings.TrimSpace(fallbackHost)
	}
	if host == "" {
		return ""
	}

	if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil {
		return parsed.String()
	}

	return strings.Trim(host, "[]")
}

// Was a network specified? E.g. --network=kraft0
func (opts *RunOptions) parseNetworks(ctx context.Context, machine *machineapi.Machine) error {
	if opts.IP != "" && len(opts.Networks) != 1 {
		return fmt.Errorf("the --ip flag only works when providing exactly one network")
	}

	if len(opts.Networks) == 0 {
		return nil
	}

	machineNetworks := []networkapi.NetworkSpec{}

	for _, networkArg := range opts.Networks {

		// The network is specified in the format
		// network:[cidr[:gw[:dns0[:dns1[:hostname[:domain]]]]]]

		split := strings.SplitN(networkArg, ":", 2)
		networkName := split[0]

		networkServiceIterator, err := network.NewNetworkV1alpha1ServiceIterator(ctx)
		if err != nil {
			return err
		}

		// Try to discover the user-provided network.
		found, err := networkServiceIterator.Get(ctx, &networkapi.Network{
			ObjectMeta: metav1.ObjectMeta{
				Name: networkName,
			},
		})
		if err != nil {
			return err
		}

		var interfaceSpec networkapi.NetworkInterfaceSpec

		if len(split) > 1 {
			fields := strings.Split(split[1], ":")
			if len(fields) > 0 && fields[0] != "" {
				interfaceSpec.CIDR = fields[0]
				ipMaskSplit := strings.SplitN(interfaceSpec.CIDR, "/", 2)
				if len(ipMaskSplit) != 2 {
					sz, _ := net.IPMask(net.ParseIP(found.Spec.Netmask).To4()).Size()
					interfaceSpec.CIDR = fmt.Sprintf("%s/%d", interfaceSpec.CIDR, sz)
				}
				opts.IP = ipMaskSplit[0]
			}

			if len(fields) > 1 {
				interfaceSpec.Gateway = fields[1]
			}
			if len(fields) > 2 {
				interfaceSpec.DNS0 = fields[2]
			}
			if len(fields) > 3 {
				interfaceSpec.DNS1 = fields[3]
			}
			if len(fields) > 4 {
				interfaceSpec.Hostname = fields[4]
			}
			if len(fields) > 5 {
				interfaceSpec.Domain = fields[5]
			}
		}

		if interfaceSpec.Gateway == "" {
			interfaceSpec.Gateway = found.Spec.Gateway
		}

		// Generate the UID pre-emptively so that we can uniquely reference the
		// network interface which will allow us to clean it up later. Additionally,
		// it's OK if the IP or MAC address are empty, the network controller will
		// populate values if they are unset and will populate with new values
		// following the returning from the Update operation.
		newIface := networkapi.NetworkInterfaceTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				UID: uuid.NewUUID(),
			},
			Spec: interfaceSpec,
		}

		// Update the list of interfaces
		if found.Spec.Interfaces == nil {
			found.Spec.Interfaces = []networkapi.NetworkInterfaceTemplateSpec{}
		}
		found.Spec.Interfaces = append(found.Spec.Interfaces, newIface)

		// Update the network with the new interface.
		found, err = networkServiceIterator.Update(ctx, found)
		if err != nil {
			return err
		}

		// Only use the single new interface.
		for _, iface := range found.Spec.Interfaces {
			if iface.UID == newIface.UID {
				newIface = iface
				break
			}
		}

		found.Spec.Interfaces = []networkapi.NetworkInterfaceTemplateSpec{newIface}
		machineNetworks = append(machineNetworks, found.Spec)
	}

	// Set the interface on the machine.
	machine.Spec.Networks = machineNetworks

	return nil
}

// assignName determines the machine instance's name either from a provided
// argument or randomly generates one.
func (opts *RunOptions) assignName(ctx context.Context, machine *machineapi.Machine) error {
	if opts.Name == "" {
		machine.ObjectMeta.Name = machinename.NewRandomMachineName(0)
		return nil
	}

	// Check if this name has been previously used
	machines, err := opts.machineController.List(ctx, &machineapi.MachineList{})
	if err != nil {
		return err
	}

	for _, found := range machines.Items {
		if opts.Name == found.Name {
			return fmt.Errorf("machine instance name already in use: %s", opts.Name)
		}
	}

	machine.ObjectMeta.Name = opts.Name

	return nil
}

// Was a volume specified? E.g. --volume=path:path
func (opts *RunOptions) parseVolumes(ctx context.Context, machine *machineapi.Machine) error {
	if len(opts.Volumes) == 0 {
		return nil
	}

	var err error
	controllers := map[string]volumeapi.VolumeService{}

	if machine.Spec.Volumes == nil {
		machine.Spec.Volumes = make([]volumeapi.Volume, 0)
	}
	for _, volLine := range opts.Volumes {
		var volName, mountPath string
		split := strings.Split(volLine, ":")
		if len(split) == 2 {
			volName = filepath.Clean(split[0])
			mountPath = filepath.Clean(split[1])
		} else {
			return fmt.Errorf("invalid syntax for --volume=%s expected --volume=<host>:<machine>", volLine)
		}

		var driver string

		for sname, strategy := range volume.Strategies() {
			if ok, _ := strategy.IsCompatible(volName, nil); !ok || err != nil {
				continue
			}

			if _, ok := controllers[sname]; !ok {
				controllers[sname], err = strategy.NewVolumeV1alpha1(ctx)
				if err != nil {
					return fmt.Errorf("could not prepare %s volume service: %w", sname, err)
				}
			}

			driver = sname
		}

		if len(driver) == 0 {
			return fmt.Errorf("could not find compatible volume driver for %s", volName)
		}

		// Check if this could be a named volume
		vol, err := controllers[driver].Get(ctx, &volumeapi.Volume{
			ObjectMeta: metav1.ObjectMeta{
				Name: volName,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to get volume: %w", err)
		}
		if vol != nil {
			vol.Spec.Destination = mountPath
			machine.Spec.Volumes = append(machine.Spec.Volumes, *vol)
			continue
		}

		vol, err = controllers[driver].Create(ctx, &volumeapi.Volume{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-%d", machine.ObjectMeta.Name, len(machine.Spec.Volumes)),
			},
			Spec: volumeapi.VolumeSpec{
				Driver:      driver,
				Source:      volName,
				Destination: mountPath,
				ReadOnly:    false, // TODO(nderjung): Options are not yet supported.
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create volume: %w", err)
		}

		machine.Spec.Volumes = append(machine.Spec.Volumes, *vol)
	}

	return nil
}

// Were any volumes supplied in the Kraftfile
func (opts *RunOptions) parseKraftfileVolumes(ctx context.Context, project app.Application, machine *machineapi.Machine) error {
	if project.Volumes() == nil {
		return nil
	}

	var err error
	controllers := map[string]volumeapi.VolumeService{}
	if machine.Spec.Volumes == nil {
		machine.Spec.Volumes = make([]volumeapi.Volume, 0)
	}

	for _, volcfg := range project.Volumes() {
		driver := volcfg.Driver()

		if len(driver) == 0 {
			for sname, strategy := range volume.Strategies() {
				if ok, _ := strategy.IsCompatible(volcfg.Source(), nil); !ok || err != nil {
					continue
				}

				if _, ok := controllers[sname]; !ok {
					log.G(ctx).WithField("volume strategy", sname).Debug("found volume strategy")
					controllers[sname], err = strategy.NewVolumeV1alpha1(ctx)
					if err != nil {
						return fmt.Errorf("could not prepare %s volume service: %w", sname, err)
					}
				}

				driver = sname
			}
		} else {
			strategy, exists := volume.Strategies()[driver]
			if !exists {
				return fmt.Errorf("unknown volume driver %s specified", driver)
			}
			if ok, _ := strategy.IsCompatible(volcfg.Source(), nil); !ok || err != nil {
				return fmt.Errorf("volume driver %s is incompatible with source %s", driver, volcfg.Source())
			}
			if _, ok := controllers[driver]; !ok {
				log.G(ctx).WithField("volume strategy", driver).Debug("found volume strategy")
				controllers[driver], err = strategy.NewVolumeV1alpha1(ctx)
				if err != nil {
					return fmt.Errorf("could not prepare %s volume service: %w", driver, err)
				}
			}
		}

		if len(driver) == 0 {
			return fmt.Errorf("could not find compatible volume driver for %s", volcfg.Source())
		}

		// Check if this could be a named volume
		vol, err := controllers[driver].Get(ctx, &volumeapi.Volume{
			ObjectMeta: metav1.ObjectMeta{
				Name: volcfg.Source(),
			},
		})

		if err == nil && vol != nil && vol.Spec.Source != "" {
			vol.Spec.Destination = volcfg.Destination()
			machine.Spec.Volumes = append(machine.Spec.Volumes, *vol)
			continue
		}

		vol, err = controllers[driver].Create(ctx, &volumeapi.Volume{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-%d", machine.ObjectMeta.Name, len(machine.Spec.Volumes)),
			},
			Spec: volumeapi.VolumeSpec{
				Driver:      driver,
				Source:      volcfg.Source(),
				Destination: volcfg.Destination(),
				ReadOnly:    volcfg.ReadOnly(),
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create volume: %w", err)
		}

		machine.Spec.Volumes = append(machine.Spec.Volumes, *vol)
	}

	return nil
}

// parse the provided `--rootfs` flag which ultimately is passed into the
// dynamic Initrd interface which either looks up or constructs the archive
// based on the value of the flag.
func (opts *RunOptions) prepareRootfs(ctx context.Context, machine *machineapi.Machine) error {
	// If the user has supplied an initram path, set this now, this overrides any
	// preparation and is considered higher priority compared to what has been set
	// prior to this point.
	if opts.Rootfs == "" || machine.Status.InitrdPath != "" || opts.RootfsType == "" {
		return nil
	}

	machine.Status.InitrdPath = filepath.Join(
		opts.workdir,
		unikraft.BuildDir,
		fmt.Sprintf(initrd.DefaultInitramfsArchFileName, machine.Spec.Architecture, opts.RootfsType),
	)

	ramfs, err := initrd.New(ctx,
		opts.Rootfs,
		initrd.WithOutput(machine.Status.InitrdPath),
		initrd.WithCacheDir(filepath.Join(
			opts.workdir,
			unikraft.BuildDir,
			"rootfs-cache",
		)),
		initrd.WithArchitecture(machine.Spec.Architecture),
		initrd.WithWorkdir(opts.workdir),
		initrd.WithOutputType(opts.RootfsType),
	)
	if err != nil {
		return fmt.Errorf("could not prepare initramfs: %w", err)
	}

	if machine.Spec.Env == nil {
		machine.Spec.Env = make(map[string]string)
	}
	treemodel, err := processtree.NewProcessTree(
		ctx,
		[]processtree.ProcessTreeOption{
			processtree.IsParallel(false),
			processtree.WithRenderer(
				log.LoggerTypeFromString(config.G[config.KraftKit](ctx).Log.Type) != log.FANCY,
			),
			processtree.WithFailFast(true),
		},
		processtree.NewProcessTreeItem(
			fmt.Sprintf("building rootfs via %s", ramfs.Name()),
			machine.Spec.Architecture,
			func(ctx context.Context) error {
				if _, err = ramfs.Build(ctx); err != nil {
					return err
				}

				for _, entry := range ramfs.Env() {
					k, v, ok := strings.Cut(entry, "=")
					if !ok {
						continue
					}

					machine.Spec.Env[k] = v
				}

				if len(machine.Spec.ApplicationArgs) == 0 {
					machine.Spec.ApplicationArgs = ramfs.Args()
				}

				return nil
			},
		),
	)
	if err != nil {
		return err
	}

	return treemodel.Start()
}

func (opts *RunOptions) parseKraftfileEnv(_ context.Context, project app.Application, machine *machineapi.Machine) error {
	if project.Env() == nil {
		return nil
	}

	if machine.Spec.Env == nil {
		machine.Spec.Env = make(map[string]string)
	}

	for k, v := range project.Env() {
		if v != "" {
			machine.Spec.Env[k] = v
			continue
		}

		if v, ok := os.LookupEnv(k); ok {
			machine.Spec.Env[k] = v
		}
	}

	return nil
}

func (opts *RunOptions) parseEnvs(_ context.Context, machine *machineapi.Machine) error {
	if machine.Spec.Env == nil {
		machine.Spec.Env = make(map[string]string)
	}

	for _, env := range opts.Env {
		k, v, ok := strings.Cut(env, "=")
		if ok {
			machine.Spec.Env[k] = v
		} else if v, ok := os.LookupEnv(k); ok {
			machine.Spec.Env[k] = v
		}
	}

	return nil
}
