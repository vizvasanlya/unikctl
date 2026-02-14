# Public Release Guide

This guide is for two audiences:

- Users: install `unikctl` and run it directly (`unikctl build`, `unikctl deploy`, `unikctl logs`, `unikctl status`, `unikctl destroy`).
- Maintainers: publish binaries so the install commands work for everyone.

## User Install Options

### 1) Install from GitHub Releases (recommended)

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-unix.sh | sh
unikctl --version
```

Windows PowerShell:

```powershell
iwr https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-windows.ps1 -OutFile install-unikctl.ps1
.\install-unikctl.ps1
unikctl --version
```

### 2) Manual binary download

1. Open `https://github.com/unikctl/unikctl/releases/latest`
2. Download the matching archive for your OS/arch.
3. Extract `unikctl` (or `unikctl.exe`) and place it in your `PATH`.
4. Run `unikctl --version`.

### 3) Build from source with Git

```bash
git clone https://github.com/unikctl/unikctl.git
cd unikctl
go build -o ./unikctl ./cmd/unikctl
./unikctl --version
```

### 4) Run via Docker (no host install)

If you publish `ghcr.io/unikctl/unikctl:<tag>`:

```bash
docker run --rm -it ghcr.io/unikctl/unikctl:latest unikctl --version
```

To use local source directory:

```bash
docker run --rm -it -v "$PWD:/workspace" -w /workspace ghcr.io/unikctl/unikctl:latest unikctl build .
```

### 5) Use from Node package scripts (npm / pnpm / yarn)

After installing `unikctl` once on the machine, call it in project scripts:

```json
{
  "scripts": {
    "unik:build": "unikctl build .",
    "unik:deploy": "unikctl deploy .",
    "unik:logs": "unikctl logs my-app --follow",
    "unik:status": "unikctl status",
    "unik:destroy": "unikctl destroy my-app"
  }
}
```

Then run:

```bash
npm run unik:build
npm run unik:deploy
```

## Maintainer Release Steps

### 1) Tag a version

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 2) Build release artifacts

```bash
make CHANNEL=stable build
```

This generates release artifacts from `.goreleaser-stable.yaml`.

### 3) Publish GitHub release

Run GoReleaser in CI or locally with required credentials:

```bash
GITHUB_TOKEN=... goreleaser release --config goreleaser-stable.yaml --clean
```

### 4) Validate install flows

Run:

```bash
curl -fsSL https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-unix.sh | sh
unikctl --version
unikctl build --help
unikctl deploy --help
unikctl logs --help
unikctl status --help
unikctl destroy --help
```

### 5) (Optional) Package manager channels

You can publish formulas/manifests for:

- Homebrew tap
- Scoop (Windows)
- Chocolatey (Windows)
- AUR (Arch)

Keep those channels pinned to the same GitHub release artifacts to avoid drift.

