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

By default, runtime builds use the in-repo runtime sources in `runtimes/*`.
If an external runtime repo input is misconfigured or unavailable, the build script falls back to local sources automatically when available.

GitHub Actions workflow for source builds:
- `.github/workflows/build-runtimes.yml`
- `.github/workflows/runtime-quality.yml`

Digest lock file used by runtime resolution:
- `internal/runtimeutil/runtime-lock.json`

Lock generation enforces non-empty digests for core runtimes (`base,nodejs,python,java,dotnet`) so release deployments do not depend on floating tags.

Runtime source layout options:
- Multi-repo: one runtime source repo per image (`base`, `nodejs`, `python`, `java`, `dotnet`)
- Monorepo: one repo with per-runtime subdirs, and set workflow inputs:
  - `source_repo_template=.`
  - `base_subdir`, `nodejs_subdir`, `python_subdir`, `java_subdir`, `dotnet_subdir`

This repository ships default monorepo runtime sources at:
- `runtimes/base`
- `runtimes/nodejs`
- `runtimes/python`
- `runtimes/java`
- `runtimes/dotnet`

Runtime source projects can use `unik.yaml`; `Kraftfile` generation is handled internally by the runtime builder.

Registry operations in runtime scripts/workflows use Go registry APIs and do not require a Docker daemon.

## Native Source Pipeline

For source-first projects (without a `Kraftfile`), `unikctl` detects the project type and builds a native rootfs pipeline automatically.

Supported packs include common flows such as:
- Node.js / React static bundles
- Python service projects
- Go services

If `unik.yaml` is missing, `unikctl` auto-generates a default one during native builds.
For Python projects where entrypoint detection fails, `unikctl` writes a starter `unik.yaml` template with a `uvicorn` command so you can edit and rerun quickly.

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
