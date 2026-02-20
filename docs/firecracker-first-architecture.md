# Firecracker-First Architecture (v2)

## Textual Architecture Diagram

```
                      +---------------------------+
CLI (unikctl)  -----> | Control Plane API (TLS)  |
                      | AuthN/AuthZ + RateLimit  |
                      +-------------+-------------+
                                    |
                                    v
                      +---------------------------+
                      | Durable Job Queue (WAL)  |
                      | lease-claim + retries    |
                      +-------------+-------------+
                                    |
                                    v
                      +---------------------------+
                      | Scheduler/Admission       |
                      | strict CPU+MEM checks     |
                      | spread/binpack/priority   |
                      +------+------+-------------+
                             |      |
                   local run |      | remote forwarding
                             v      v
               +----------------+  +--------------------+
               | Node Agent(s)  |  | Node Agent(s) ...  |
               | heartbeat/caps |  | heartbeat/caps     |
               +--------+-------+  +---------+----------+
                        |                    |
                        v                    v
           +----------------------+  +----------------------+
           | Machine Lifecycle    |  | Machine Lifecycle    |
           | Firecracker (full)   |  | QEMU (partial)       |
           +----------+-----------+  +----------+-----------+
                      |
                      v
           +------------------------------+
           | Warm Pool + Snapshot GC      |
           | pause/snapshot/resume paths  |
           +------------------------------+
```

## Key Interfaces

- `machine/lifecycle.MachineLifecycle`
  - `Create`
  - `Start`
  - `Pause`
  - `Resume`
  - `Snapshot`
  - `Restore`
  - `Stop`
  - `Destroy`
  - `Inspect`

- `machine/resources`
  - `ApplyDefaultsAndValidate`
  - `BackfillMissingFromPlatform`
  - `Validate`

## Persistence Changes

Legacy JSON stores were replaced by WAL-backed Badger stores:

- `operations.db`
- `workloads.db`
- `nodes.db`
- `services.db`
- `jobs.db`
- `warm_pool.db`

## Security Changes

- TLS required by default for control-plane API.
- Insecure HTTP now requires explicit `allow_insecure_http`.
- Unauthenticated mode requires explicit `allow_unauthenticated`.
- JWT validation enforces:
  - signature (HS256),
  - `exp` claim,
  - optional configured `iss` and `aud`,
  - scope checks.
- Per-endpoint rate limiting enabled.

## Breaking Changes

1. Control-plane no longer defaults to unauthenticated access.
2. Control-plane no longer defaults to plain HTTP unless explicitly allowed.
3. Invalid CPU/memory requests now fail admission with structured errors.
4. Scheduler no longer silently falls back to mutated resource defaults.
5. Firecracker is prioritized as default platform iteration order.

## Migration Notes

1. Configure TLS for control-plane:
   - `control_plane.tls_cert_file`
   - `control_plane.tls_key_file`

2. Configure authentication (one of):
   - `control_plane.token`
   - `control_plane.rbac_tokens`
   - `control_plane.jwt_hs256_secret` (+ optional issuer/audience)

3. If you must run insecure during migration only:
   - set `control_plane.allow_insecure_http=true`
   - set `control_plane.allow_unauthenticated=true` (not recommended)

4. Ensure deploy requests provide valid CPU/memory quantities.

5. Optional warm pool settings:
   - `UNIKCTL_WARM_POOL_SIZE`
   - `UNIKCTL_WARM_POOL_IDLE_TIMEOUT_SECONDS`
   - `UNIKCTL_WARM_POOL_GC_SECONDS`
