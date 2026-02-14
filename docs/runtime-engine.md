# Runtime Engine (Image Backbone)

`unikctl` deploys apps by combining:
- your app/rootfs artifact
- a runtime image (`base`, `nodejs`, `python`, `java`, `dotnet`)

After rebranding, runtime images are expected in:
- `ghcr.io/vizvasanlya/unikctl/*`

## Quick Start (No Prior Knowledge)

1. Login to GHCR:

```bash
echo "$GHCR_PAT" | docker login ghcr.io -u vizvasanlya --password-stdin
```

2. Mirror runtime images from upstream into your namespace:

```bash
cd /path/to/unikctl-rebrand
./scripts/publish-runtimes.sh
```

Windows PowerShell:

```powershell
cd D:\kernel\unikctl-rebrand
.\scripts\publish-runtimes.ps1
```

With retry hardening:

```bash
RETRIES=5 ./scripts/publish-runtimes.sh
```

Required vs optional behavior:

- `REQUIRED_IMAGES` controls which images must exist at source (default: `base`).
- Missing optional images are skipped with warning.
- Missing required images fail the publish.

```bash
REQUIRED_IMAGES=base,nodejs ./scripts/publish-runtimes.sh
```

Per-runtime explicit source override:

```bash
SOURCE_NODEJS=<registry>/<repo>/nodejs:latest ./scripts/publish-runtimes.sh
```

PowerShell:

```powershell
$env:SOURCE_NODEJS = "<registry>/<repo>/nodejs:latest"
.\scripts\publish-runtimes.ps1
```

3. Verify one image:

```bash
docker buildx imagetools inspect ghcr.io/vizvasanlya/unikctl/base:latest
```

4. Deploy:

```bash
unikctl deploy .
```

## Publish via GitHub Actions

Workflow:
- `.github/workflows/publish-runtimes.yml`

How to use:
1. Open `Actions` -> `publish-runtimes`.
2. Click `Run workflow`.
3. Keep defaults (`source_prefix=unikraft.org`, `target_prefix=ghcr.io/vizvasanlya/unikctl`, `images=base,nodejs,python,java,dotnet`, `tags=latest`).
4. Use `required_images` if you want strict fail for additional runtimes.

## Optional: publish release tag too

```bash
TAGS=latest,v0.1.11 ./scripts/publish-runtimes.sh
```

## Why this matters

If these images are missing, `unikctl build/deploy` can fail at runtime lookup/pull.

## Production baseline recommendation

1. Publish required runtimes before each public CLI release.
2. Keep `latest` plus a version tag (for example `v0.1.12`).
3. Run `unikctl doctor` on deployment hosts to verify runtime image availability.
4. Treat runtime images as release artifacts and patch regularly.
