# unikctl Cloud Blueprint

## Product Contract

Single CLI surface:

- `unikctl build [DIR]`
- `unikctl deploy [PROJECT|PACKAGE|BINARY]`
- `unikctl logs APP`
- `unikctl status`
- `unikctl destroy APP [APP...]`

Build modes:

- Default: `release` (small, stripped image)
- Optional: `--debug` (symbols/tracing)

No-Docker guarantee:

- `unikctl build` rejects Dockerfile rootfs paths.
- Source builds run via host toolchains or custom `unik.yaml`.
- Users never need Docker to build, deploy, inspect, or destroy workloads.

Non-goals for v1:

- No SSH
- No interactive shell
- No on-host log files exposed to app

## Runtime Model

1. `build`: Convert app input to unikernel boot artifact.
2. `deploy`: Start VM asynchronously (CLI returns fast).
3. `logs`: Stream STDOUT from serial console pipeline.
4. `status`: Show lifecycle state of deployed instances.
5. `destroy`: Stop and remove deployment artifacts.

## Source Build Contract

Native packs:

- `go` (`go.mod` detected)
- `rust` (`Cargo.toml` detected)
- `node` (`package.json` detected)
- `python` (`requirements.txt`, `pyproject.toml`, or `*.py`)
- `java` (`pom.xml` or `build.gradle`)
- `dotnet` (`*.csproj` or `*.sln`)

Universal pack:

- `unik.yaml` with `build.command` and `artifact.path` for any language/toolchain.

Release/debug behavior:

- `release`: stripped app artifacts where supported.
- `debug`: symbolic app artifacts where supported, plus debug kernel output.

## Logging Pipeline (Required First-Class Path)

Inside guest:

- App writes to STDOUT/STDERR only.

Host/runtime:

- Hypervisor serial console captures output.
- Runtime multiplexes output into log stream.

CLI:

- `unikctl logs <app>` tails the stream.
- `--follow` remains optional for continuous tailing.

## Async Operations

`deploy` and `destroy` must not block on long operations.

- Trigger operation
- Return immediately with deployment name/ID
- Poll via `unikctl status`
- Inspect output via `unikctl logs`

Implementation note:

- `deploy` on a source directory now triggers an inline build step before runtime execution.

## Security Baseline

- No guest shell
- No package manager in guest image
- No mutable root filesystem in release mode
- Minimal syscall and device surface by target platform

## Control Plane Milestones

Phase A (single-node):

- Local machine service for async lifecycle operations.
- Serial-console log transport as the canonical log path.

Phase B (cluster-ready):

- Operation queue with idempotent `deploy`/`destroy`.
- Stateful status model (`pending`, `running`, `exited`, `failed`).
- Metering hooks (CPU, memory, boot latency, image size).
- Node-agent registration + heartbeat with capacity reports.
- Scheduler placement by node health, labels, and free CPU/RAM.
- Node cordon/drain with rescheduling.

Phase C (production cloud):

- API gateway + authn/authz.
- Tenant-aware quotas, placement, and rollout policy.
- SLO dashboards: boot latency p50/p95, deploy success rate, cost per request.

Current implementation note:

- Idempotency keys are now attached to `deploy`/`destroy` requests.
- Queued jobs are persisted and replayed on control-plane restart.
- Automatic retries with backoff are enabled for failed queued operations.
- API errors now include stable machine-readable `code` and `trace_id`.
- Control-plane supports bearer token auth, static RBAC token scopes, optional HS256 JWT validation, and optional TLS cert/key.
- `GET /v1/metrics` exports operation latency/failure/retry counters in Prometheus format.

## Legal and Fork Compliance

Because this is derived from Unikraft/KraftKit:

- Keep upstream license files intact (`BSD-3-Clause`).
- Keep copyright/author attribution.
- Do not imply official sponsorship by Unikraft.
- Rename product/CLI branding (`unikctl`) in user-facing UX.
- Maintain a fork notice in docs.

## Delivery Phases

Phase 1:

- Rebrand fork and module path.
- Enforce 5-command surface.
- Ensure `build --debug` support.
- Ensure deploy is async-by-default.

Phase 2:

- Stabilize serial-console log transport.
- Add operation IDs and status lifecycle states.
- Add golden-path tests for `build/deploy/logs/status/destroy`.

Current implementation note:

- `deploy` and `destroy` persist operation records in the runtime directory.
- `status` renders recent operation state plus machine state in one view.

Phase 3:

- Cloud control plane API integration.
- Multi-tenant isolation and quotas.
- CI release pipeline and signed artifacts.
- Benchmark harness proving boot latency and density improvements.

## Implemented Control Plane API (single-node)

The internal control-plane service currently exposes:

- `POST /v1/artifacts` -> upload local source bundle for remote deploy
- `POST /v1/deployments` -> enqueue deploy operation
- `POST /v1/destroy` -> enqueue destroy operation
- `GET /v1/status` -> machine status + recent operation state + node inventory
- `GET /v1/logs/{machine}` -> log streaming proxy
- `GET /healthz` -> liveness probe
- `POST /v1/nodes/register` -> node-agent registration
- `POST /v1/nodes/heartbeat` -> node-agent heartbeat + capacity update
- `POST /v1/nodes/{name}/cordon` -> cordon node
- `POST /v1/nodes/{name}/uncordon` -> uncordon node
- `POST /v1/nodes/{name}/drain` -> drain + reschedule workloads
- `GET /v1/metrics` -> Prometheus metrics export

Runtime behavior:

- Persistent operation journal backed by runtime storage.
- Async worker queue with configurable concurrency.
- CLI remote mode via `UNIKCTL_CONTROL_PLANE_URL`.
- Deploy automatically uploads local source inputs and local `--rootfs` inputs and stages them on control-plane host.
- Runtime names are normalized to fully-qualified references with fallback candidate resolution.
- Native source build packs enforce deterministic lock inputs in release mode.
- Native source pipeline emits `.unikctl/native/pack-metadata.json`.
- Build-tool dependency caches are reused from `.unikctl/cache`.
- Remote node execution forwarding is performed through node-agent APIs.
- Workload placement metadata is persisted for destroy/log forwarding and drain rescheduling.
