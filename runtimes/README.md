# Runtime Sources

This directory contains in-repo runtime source projects used by:
- `.github/workflows/build-runtimes.yml`
- `.github/workflows/publish-runtimes.yml`

Each runtime project uses `unik.yaml` and optionally a `Dockerfile`.
The runtime build tool generates an internal `Kraftfile` automatically, so runtime maintainers do not need to author one.
