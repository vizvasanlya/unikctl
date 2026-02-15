# unikctl

`unikctl` is a no-OS application platform CLI.

It provides a simple product surface:
- `unikctl build`
- `unikctl deploy`
- `unikctl logs`
- `unikctl status`
- `unikctl destroy`

Default behavior is optimized for production (`release` mode). Use `--debug` when you need symbols and tracing.

## Install

### Linux/macOS
```sh
curl -fsSL https://raw.githubusercontent.com/vizvasanlya/unikctl/main/scripts/install-unix.sh | sh
unikctl --version
```

### Windows (PowerShell)
```powershell
iwr https://raw.githubusercontent.com/vizvasanlya/unikctl/main/scripts/install-windows.ps1 -UseBasicParsing | iex
unikctl --version
```

## Quick Start

### 1) Build
```sh
unikctl build
```

### 2) Deploy
```sh
unikctl deploy .
```

### 3) Check status and launch URL
```sh
unikctl status
```

`status` prints deployment state and the launch URL when available.

### 4) View logs
```sh
unikctl logs <app-name>
```

### 5) Destroy
```sh
unikctl destroy <app-name>
```

## Build Modes

- `release` (default): small, locked-down image for production.
- `debug`: adds debug symbols and tracing metadata.

```sh
unikctl build --debug
```

## Runtime Namespace

`unikctl` resolves runtimes and packaged images under your GHCR namespace.

Default namespace used by this repository:
- `ghcr.io/vizvasanlya/unikctl`

You can build and publish runtimes from source (not mirroring) with:
```sh
./scripts/build-runtimes-from-source.sh
```

GitHub Actions workflow for source builds:
- `.github/workflows/build-runtimes.yml`

Digest lock file used by runtime resolution:
- `internal/runtimeutil/runtime-lock.json`

## Native Source Pipeline

For source-first projects (without a `Kraftfile`), `unikctl` detects the project type and builds a native rootfs pipeline automatically.

Supported packs include common flows such as:
- Node.js / React static bundles
- Python service projects
- Go services

## Control Plane and Nodes

`unikctl` includes:
- async operations tracking
- node registration and heartbeat
- scheduler placement
- node cordon/drain management

Key commands:
```sh
unikctl node list
unikctl node cordon <node-id>
unikctl node uncordon <node-id>
unikctl node drain <node-id>
```

## Diagnostics

Use `doctor` to validate host prerequisites:
```sh
unikctl doctor
```

## Repository Layout

- `cmd/unikctl`: CLI entry point
- `internal/cli/unikctl`: command implementation
- `scripts/`: install and runtime publishing scripts
- `.github/workflows/`: release and CI workflows
- `docs/`: architecture and operations docs

## Release

Tag and push a semver tag:
```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds binaries and publishes assets.

## License

BSD-3-Clause. See `LICENSE.md` and `FORK_NOTICE.md`.
