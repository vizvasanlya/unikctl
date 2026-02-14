# unikctl 🚀🐒🧰

[![](https://pkg.go.dev/badge/unikctl.sh.svg)](https://pkg.go.dev/unikctl.sh)
![](https://img.shields.io/static/v1?label=license&message=BSD-3&color=%23385177)
[![](https://img.shields.io/discord/762976922531528725.svg?label=discord&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)][unikraft-discord]
[![Go Report Card](https://goreportcard.com/badge/unikctl.sh)](https://goreportcard.com/report/unikctl.sh)
![Latest release](https://img.shields.io/github/v/release/unikctl/unikctl)

unikctl provides a suite of tools and Go-based framework for building custom, minimal, immutable lightweight unikernel virtual machines based on [Unikraft](https://unikraft.org): a fast, secure and open-source library operating system.

This repository is a rebranded fork of Unikraft's KraftKit. BSD-3-Clause license terms and attribution are intentionally preserved.

![](docs/demo.gif)

With unikctl, you can easily leverage Unikraft and manage specialized, high-performance applications at every stage of their lifecycle: from construction to production.

 * [Getting started guide][unikctl-getting-started] 📖
 * [Key differences between containers and unikernels](https://unikraft.org/docs/concepts/) 🤔
 * [Join `#unikctl` on Unikraft's Community Discord](https://bit.ly/UnikraftDiscord) 👾

There are many benefits in running your application as a unikernel: for more information about [the performance of unikernels 🚀](https://unikraft.org/docs/features/performance/), [the added security 🔒](https://unikraft.org/docs/features/security/) and [a positive impact on the environment 🌱](https://unikraft.org/docs/features/green/) please [check out Unikraft's documentation][unikraft-docs] and the introductory chapters on these impacts


## Features

- 🚧 Build, run and package unikernel VMs;
- 🧱 Docker-free source builds (`go`, `rust`, `node`, `python`, `java`, `dotnet`, and custom `unik.yaml` pipelines);
- 📚 Fetch and run pre-built unikernel from the [app catalog](https://github.com/unikraft/catalog);
- 🔥 Run unikernel VMs using QEMU, Xen and [Firecracker MicroVM](https://firecracker-microvm.github.io/);
- 🤹‍♀️ Daemonless unikernel local VM instance manager;
- ⛅️ Deploy unikernel VMs to the [cloud](https://unikraft.cloud);
- 🍎 Native Linux, macOS and Windows support;
- 📦 Package and push unikernels in OCI format for easy distribution;
- 🚜 ELF binary / POSIX-compatibility support;
- 🧰 Go SDK for building unikernels programmatically; and
- 🚀 _much more!_


## Installation

Recommended install options:

- GitHub release installer (Linux/macOS):
```bash
curl -fsSL https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-unix.sh | sh
```

- GitHub release installer (Windows PowerShell):
```powershell
iwr https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-windows.ps1 -OutFile install-unikctl.ps1
.\install-unikctl.ps1
```

- Manual binaries from [releases](https://github.com/unikctl/unikctl/releases).
- Build from source via Git (`go build -o ./unikctl ./cmd/unikctl`).
- Run from container image (`docker run ... unikctl ...`) once you publish your image.

See [additional installation instructions](https://unikraft.org/docs/cli/install).

See also the [hacking documentation on how to build unikctl from source](https://unikraft.org/docs/cli/hacking).

Full public distribution + release checklist:

- [`docs/public-release.md`](docs/public-release.md)

After install, users run `unikctl` directly:

```bash
unikctl build .
unikctl deploy .
unikctl status
unikctl logs my-app --follow
unikctl destroy my-app
```


### Host toolchain requirements

The default `unikctl` source pipeline is Docker-free.
Install the language toolchain you use on the host:

- Go projects: `go`
- Rust projects: `cargo`
- Node projects: `npm`
- Python projects: `pip`
- Java projects: `mvn` or `gradle`
- .NET projects: `dotnet`
- Other languages: define a custom `build.command` in `unik.yaml`

Run host checks:

```shell
unikctl doctor
```


## Quickstart

Full end-to-end manual process and test checklist:

- [`docs/manual-process-and-test.md`](docs/manual-process-and-test.md)

### Test your installation

Running unikernels with `unikctl` is designed to be simple and familiar.
To test your installation of `unikctl`, you can run the following:

```
unikctl status
```

### Build your first unikernel

Build from source in release mode (default):

```shell
unikctl build
```

Build a debug image (symbols + tracing):

```shell
unikctl build --debug
```

`unikctl build` no longer accepts Dockerfile-based rootfs inputs.

### Migrate from Docker/Compose

Convert an existing Dockerfile into a `unik.yaml` starter:

```shell
unikctl migrate dockerfile .
```

Convert an existing `docker-compose.yml` into a migration plan and per-service `unik.yaml` files:

```shell
unikctl migrate compose ./docker-compose.yml
```

This writes `unikctl-compose.migrated.yaml` with per-service `unikctl deploy ...` commands and generates service-level unik configs when build contexts include Dockerfiles.

For non-native languages, add a `unik.yaml` custom pipeline:

```yaml
version: v1
runtime: python:latest
build:
  command: make unik-artifact
artifact:
  path: .unik-out
run:
  command: ["python", "/app/app.py"]
```

Then deploy and stream logs:

```shell
unikctl deploy .
unikctl logs my-app --follow
# or for a rollout service:
unikctl logs storefront --follow
```

`unikctl deploy .` now auto-builds source directories before deployment.

`deploy` and `destroy` now emit an operation ID. `unikctl status` shows recent operation lifecycle state (`pending`, `running`, `submitted`, `succeeded`, `failed`) alongside machine status.

`unikctl status` now includes `SERVICE`, `PUBLIC PORT`, and `URL` columns derived from mapped ports.

### Control Plane mode

unikctl includes an internal control-plane service that exposes an HTTP API and executes deploy/destroy requests asynchronously with a worker queue.

Run control plane on a host:

```shell
UNIKCTL_CONTROL_PLANE_LISTEN=127.0.0.1:7689 unikctl control-plane
```

Point a client to that host:

```shell
export UNIKCTL_CONTROL_PLANE_URL=http://127.0.0.1:7689
unikctl deploy .
unikctl status
unikctl logs my-app --follow
unikctl destroy my-app
```

Optional API auth and RBAC scopes:

```shell
export UNIKCTL_CONTROL_PLANE_TOKEN=change-me
export UNIKCTL_CONTROL_PLANE_RBAC_TOKENS="change-me=*;ops-token=status,logs"
export UNIKCTL_CONTROL_PLANE_JWT_HS256_SECRET=replace-with-strong-secret
```

Optional TLS:

```shell
export UNIKCTL_CONTROL_PLANE_TLS_CERT_FILE=/path/tls.crt
export UNIKCTL_CONTROL_PLANE_TLS_KEY_FILE=/path/tls.key
export UNIKCTL_CONTROL_PLANE_URL=https://control-plane.example:7689
```

Notes:

- In control-plane mode, `deploy/status/logs/destroy` are served over HTTP.
- `deploy` now uploads local source paths as compressed artifacts before queueing the operation.
- `deploy --rootfs ...` uploads local rootfs paths as compressed artifacts too.
- If `--rootfs` points to a non-local path on the client, it is interpreted on the control-plane host.
- Control-plane queue jobs are persisted and replayed after restart.
- Deploy/destroy requests include idempotency keys to avoid duplicate operations.
- Failed jobs retry automatically with backoff.
- API errors include machine-readable `code` and `trace_id`.
- Metrics are exposed at `GET /v1/metrics` (Prometheus text format).
- If your local host cannot run the selected hypervisor driver (for example some Windows setups), run `unikctl control-plane` on a Linux host and use `UNIKCTL_CONTROL_PLANE_URL` from your client machine.

### Multi-node scheduler and node agents

Start central control-plane:

```shell
UNIKCTL_CONTROL_PLANE_LISTEN=0.0.0.0:7689 unikctl control-plane
```

On each worker node, run a node agent:

```shell
export UNIKCTL_NODE_CONTROL_PLANE_URL=http://<control-plane-host>:7689
export UNIKCTL_NODE_CONTROL_PLANE_TOKEN=change-me
export UNIKCTL_NODE_AGENT_TOKEN=node-agent-secret
export UNIKCTL_NODE_AGENT_ADVERTISE_URL=http://<node-host>:7780
export UNIKCTL_NODE_AGENT_LABELS="zone=us-east-1a,tier=general"
unikctl node-agent
```

Node lifecycle operations:

```shell
unikctl node list
unikctl node cordon node-a
unikctl node drain node-a
unikctl node uncordon node-a
```

Behavior:

- Deploy requests are scheduled to ready nodes using capacity (CPU/RAM) and optional selectors.
- Node agents heartbeat capacity/usage and machine counts to the control-plane.
- `drain` cordons the node and reschedules workloads to other ready nodes.
- Control-plane forwards deploy/destroy/log operations to node agents over API.

### Orchestration parity via `unik.yaml` (no extra CLI flags)

`unikctl deploy .` now reads rollout settings from `unik.yaml` and forwards them to the control-plane scheduler:

```yaml
version: v1
language: node
deploy:
  service: storefront
  replicas: 3
  strategy: rolling      # rolling | bluegreen | canary
  max_unavailable: 1     # rolling only
  max_surge: 1           # rolling only
  canary_percent: 20     # canary only
  health_check:
    path: /health
    port: 8080
    interval_seconds: 1
    timeout_seconds: 30
```

Notes:

- If `deploy.replicas > 1`, control-plane runs a service rollout instead of a single-machine deploy.
- Rollout machine names are deterministic per operation for safer retries/resume behavior.
- `unikctl status` continues to show operation state plus launch URL columns.
- `unikctl status` now also shows a service rollout summary (`SERVICE`, `STRATEGY`, `PHASE`, `READY`, `MACHINES`, `MESSAGE`, `LAST ERROR`, `LAST HEALTHY`, `UPDATED`) in control-plane mode.

### React / TypeScript source projects

For Node frontend projects with a `build` script (for example React + TypeScript):

- `unikctl build` runs `npm install` and `npm run build`.
- If static output is detected (`dist/`, `build/`, or `out/`), unikctl packages it with an embedded static HTTP server binary.
- Runtime defaults to `ghcr.io/vizvasanlya/unikctl/base:latest` for this static frontend mode.

For Python source projects:

- unikctl now auto-detects entrypoints from common files, package `__main__.py`, and `pyproject.toml` script definitions.
- You only need `run.command` in `unik.yaml` for custom or ambiguous startup flows.

Runtime resolution behavior:

- Runtime aliases are normalized to fully-qualified references (for example `nodejs:latest` -> `ghcr.io/vizvasanlya/unikctl/nodejs:latest`).
- Runtime lookup uses fallback candidates when the first reference is unavailable.

Deterministic release behavior:

- `release` mode requires lock inputs for deterministic dependency resolution.
- Node: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, or `pnpm-lock.yaml`.
- Python: `requirements.txt`, `poetry.lock`, or `uv.lock`.
- Rust: `Cargo.lock`.
- Go: `go.sum`.

Build-pack metadata and cache:

- Native pipeline writes `.unikctl/native/pack-metadata.json` with selected pack/runtime/command/mode.
- Repeated builds reuse `.unikctl/cache` (`npm`, `pip`, `cargo`, `go`) to reduce rebuild time.
- Runtime image backbone setup is documented in `docs/runtime-engine.md`.

## Benchmark harness

Run benchmark harness locally:

```shell
go build -o ./unikctl ./cmd/unikctl
go run ./tools/benchharness --binary ./unikctl --iterations 3
```

Artifacts:

- `benchmark-results.json` (deploy latency, boot time, failure rate, iteration details)
- `benchmark-metrics.txt` (control-plane Prometheus metrics snapshot)

A CI workflow is included at `.github/workflows/benchmark-harness.yaml`.

### Examples and pre-built images

You can find some common project examples below:

| | Example |
|-|:-|
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/c.svg) | [Simple "Hello, world!" application written in C](https://github.com/unikraft/catalog/tree/main/examples/helloworld-gcc13.2) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/cpp.svg) | [Simple "Hello, world!" application written in C++](https://github.com/unikraft/catalog/tree/main/examples/helloworld-g%2B%2B13.2) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/rust-white.svg#gh-dark-mode-only)![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/rust-black.svg#gh-light-mode-only) | [Simple "Hello, world!" application written in Rust built via `cargo`](https://github.com/unikraft/catalog/tree/main/examples/helloworld-rust1.75) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/js.svg) | [Simple NodeJS 18 HTTP Web Server with `http`](https://github.com/unikraft/catalog/tree/main/examples/httpserver-nodejs18) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/go.svg) | [Simple Go 1.21 HTTP Web Server with `net/http`](https://github.com/unikraft/catalog/tree/main/examples/httpserver-go1.21) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/python3.svg) | [Simple Flask 3.0 HTTP Web Server](https://github.com/unikraft/catalog/tree/main/examples/flask3.0-python3.12) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/python3.svg) | [Simple Python 3.10 HTTP Web Server with `http.server.HTTPServer`](https://github.com/unikraft/catalog/tree/main/examples/httpserver-python3.10) |

Find [more examples and applications in our community catalog](https://github.com/unikraft/catalog)!


## Use in GitHub Actions

unikctl can be used to automatically build your application into a unikernel in a GitHub Actions workflow, "`use`" `unikctl/unikctl@staging`.

In the following example, a repository that has been initialized with a top-level `Kraftfile` that contains a target for qemu/x86_64 will be built every time a PR is opened, synchronized or re-opened:

```yaml
name: example

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  build:
    steps:
    - uses: actions/checkout@v4

    - uses: unikctl/unikctl@staging
      with:
        workdir: .
        kraftfile: Kraftfile
        arch: x86_64
        plat: qemu
```

For other CI's and integrations, including GitLab, check out [the getting started guide](https://unikraft.org/docs/getting-started).


## Compatibility

| Hypervisor  | Supported Version    |
|-------------|----------------------|
| Xen         | <= 4.19              |
| QEMU        | <= 9.2.1 && >= 4.2.0 |
| Firecracker | >= 1.4.1             |

|                 | QEMU | Firecracker | Xen | [containerd](/oci/README.md#supported-backends) |
|-----------------|------|-------------|-----|-------------------------------------------------|
| `linux/amd64`   | ✅   | ✅          | ✅  | ✅                                              |
| `linux/arm64`   | ✅   | ✅          | --  | ✅                                              |
| `darwin/amd64`  | ✅   | --          | --  | ✅                                              |
| `darwin/arm64`  | ✅   | --          | --  | ✅                                              |
| `freebsd/amd64` | ✅   | --          | --  | ✅                                              |
| `freebsd/arm64` | ✅   | --          | --  | ✅                                              |
| `netbsd/amd64`  | ✅   | --          | --  | --                                              |
| `netbsd/arm64`  | ✅   | --          | --  | --                                              |
| `openbsd/amd64` | ✅   | --          | --  | --                                              |
| `openbsd/arm64` | ✅   | --          | --  | --                                              |


## Support, Community & Meetings

If you have any further questions or need more information about unikctl or Unikraft, please refer to [the official Unikraft documentation][unikraft-docs] or ask for help on the Unikraft community forum.

A unikctl Working Group (WG) meets every other Wednesday at 13:00 PM (CET) on [Discord][unikraft-discord].
Invites and additional details are available on the [Unikraft OSS Public calendar][unikraft-calendar].


## License

unikctl is part of the [Unikraft OSS Project][unikraft-website] and licensed under `BSD-3-Clause`.

[unikraft-website]: https://unikraft.org
[unikraft-docs]: https://unikraft.org/docs
[unikraft-discord]: https://bit.ly/UnikraftDiscord
[unikraft-calendar]: https://unikraft.org/community/events/
[unikctl-getting-started]: https://unikraft.org/docs/getting-started/
