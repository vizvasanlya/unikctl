# Runtime Engine (Production Notes)

`unikctl` deploys apps by combining:
- app/rootfs artifact built from source
- runtime image (`base`, `nodejs`, `python`, `java`, `dotnet`)

Runtime images are owned under:
- `ghcr.io/vizvasanlya/unikctl/*`

## No-Docker Runtime Pipeline

Runtime build and publish paths use Go registry APIs and do not require a Docker daemon:
- `scripts/build-runtimes-from-source.sh`
- `scripts/generate-runtime-lock.sh`
- `scripts/publish-runtimes.sh`
- `tools/registrydigest`
- `tools/registrycopy`

Auth is read from `~/.docker/config.json` (credential file only).

## Default Runtime Source Layout

The repository ships in-repo runtime sources:
- `runtimes/base`
- `runtimes/nodejs`
- `runtimes/python`
- `runtimes/java`
- `runtimes/dotnet`

Each runtime source is defined by `unik.yaml`. The runtime builder auto-generates internal manifest files and does not require users to author `Kraftfile`.

## Build Runtimes

Local:

```bash
cd /path/to/unikctl-rebrand
./scripts/build-runtimes-from-source.sh
./scripts/generate-runtime-lock.sh
```

Notes:
- Runtime source build defaults to in-repo runtime directories (`runtimes/base`, `runtimes/nodejs`, `runtimes/python`, `runtimes/java`, `runtimes/dotnet`).
- If external runtime source inputs are wrong or unavailable, the build script falls back to in-repo runtime sources when present.
- Lock generation fails if required runtime digests are missing, preventing incomplete lockfiles from being committed.

GitHub Actions:
- `.github/workflows/build-runtimes.yml`
- `.github/workflows/publish-runtimes.yml`
- `.github/workflows/runtime-quality.yml`

## Validate Production Quality

`runtime-quality` workflow performs:
1. Runtime source contract checks (`tools/runtimecheck`)
2. Runtime build matrix (`base,nodejs,python,java,dotnet`)
3. Digest verification after publish

## Why This Matters

If runtime images are not published and reachable, `unikctl build/deploy` fails at runtime lookup.

Use digest pinning (`internal/runtimeutil/runtime-lock.json`) for reproducible deploys.
