# unikctl WSL Self-Test Guide (Windows + WSL2)

This guide is for running a full manual self-test on a Windows machine using WSL2 (Ubuntu).

It covers:
- install from release (`curl`)
- optional clone-from-git workflow
- end-to-end command testing (`build`, `deploy`, `status`, `logs`, `inspect`, `destroy`)
- control-plane/node tests
- benchmark/substrate checks
- cleanup/reset

## 1) What You Need

Minimum:
- Windows 10/11 with virtualization enabled
- WSL2 Ubuntu
- Internet access

Inside WSL (Ubuntu), install dependencies:

```bash
sudo apt update
sudo apt install -y curl tar ca-certificates qemu-system-x86 qemu-utils python3 python3-pip nodejs npm
```

Quick verify:

```bash
qemu-system-x86_64 --version
python3 --version
node --version
npm --version
```

Notes:
- Local deploy testing needs Linux userspace. WSL2 is valid.
- If `/dev/kvm` is unavailable in WSL, deploy still works but slower (software emulation).
- Firecracker is the preferred/default driver when available, but in WSL local testing QEMU is commonly used as fallback.
- `unikctl doctor` currently validates QEMU availability, so `qemu-system-x86_64` is included in this checklist.

## 2) Use Linux Filesystem (Important)

Do tests in WSL home paths (fast), not `/mnt/c` or `/mnt/d` (slow for many files):

```bash
mkdir -p ~/apps/unikctl-tests
cd ~/apps/unikctl-tests
```

## 3) Install unikctl From Release (curl)

```bash
curl -fsSL https://raw.githubusercontent.com/vizvasanlya/unikctl/main/scripts/install-unix.sh | sh
unikctl --version
```

Expected:
- installer prints `downloading ...`
- installer prints `installed: /usr/local/bin/unikctl`
- `unikctl --version` prints your installed version

If you want a specific version:

```bash
UNIKCTL_VERSION=v0.4.0 curl -fsSL https://raw.githubusercontent.com/vizvasanlya/unikctl/main/scripts/install-unix.sh | sh
```

## 4) Optional: Clone From Git Too

If you also want the repository locally for docs/scripts:

```bash
cd ~/apps
git clone https://github.com/vizvasanlya/unikctl.git
cd unikctl
```

You do not need to build from source for this self-test. The released binary from step 3 is enough.

## 5) Preflight Health Check

```bash
unikctl doctor
```

Expected:
- `qemu` should be `PASS`
- `network` should be `PASS`
- `runtime-registry` should be `PASS` or `WARN`
- if any `FAIL`, fix that before proceeding

## 6) Test A: Frontend (React)

Create a sample app:

```bash
cd ~/apps/unikctl-tests
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
```

Build:

```bash
unikctl build
```

Expected:
- `native source pipeline selected language_pack=node mode=release`
- build completes and prints `Build completed successfully`

Deploy:

```bash
unikctl deploy .
```

Expected:
- `operation: op-...`
- app/machine name line (for example `focused_...`)
- `launch: http://127.0.0.1:<port>`

Check status:

```bash
unikctl status
```

Expected:
- operations table shows deploy state as `deploying` then `running`
- machine table has columns `SERVICE`, `PUBLIC PORT`, `URL`
- `URL` should show `http://127.0.0.1:<port>`

View logs:

```bash
unikctl logs <app-name>
```

Expected:
- serial/stdout logs from inside the unikernel

Inspect:

```bash
unikctl inspect <app-name>
```

Expected:
- resource requests (cpu/memory)
- driver/platform details
- snapshot fields (`snapshot_state`, `snapshot_path`, etc.)

Destroy:

```bash
unikctl destroy <app-name>
unikctl status
```

Expected:
- operation becomes `destroyed`
- machine no longer shown as running

## 7) Test B: Python Backend

Create minimal backend:

```bash
cd ~/apps/unikctl-tests
mkdir -p backend/app
cd backend
cat > requirements.txt <<'EOF'
fastapi==0.110.0
uvicorn==0.29.0
EOF
cat > app/main.py <<'EOF'
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}
EOF
cat > unik.yaml <<'EOF'
runtime: ghcr.io/vizvasanlya/unikctl/python:latest
run:
  command:
    - python
    - -m
    - uvicorn
    - app.main:app
    - --host
    - 0.0.0.0
    - --port
    - "8000"
EOF
```

Build and deploy:

```bash
unikctl build
unikctl deploy .
unikctl status
unikctl logs <app-name>
```

Expected:
- launch URL on host port (for example `http://127.0.0.1:8000`)
- logs show app startup

If deployment fails with memory/cpio extraction errors, retry with higher memory:

```bash
unikctl deploy . --memory 256Mi
```

## 8) Control-Plane + Node Test (Advanced)

Terminal A (start control-plane locally in test mode):

```bash
export UNIKCTL_CONTROL_PLANE_LISTEN=127.0.0.1:7689
export UNIKCTL_CONTROL_PLANE_ALLOW_INSECURE_HTTP=1
export UNIKCTL_CONTROL_PLANE_ALLOW_UNAUTHENTICATED=1
unikctl control-plane
```

Terminal B (client commands):

```bash
export UNIKCTL_CONTROL_PLANE_URL=http://127.0.0.1:7689
unikctl status
unikctl substrate status
unikctl bench boot --control-plane-url http://127.0.0.1:7689
unikctl bench density --control-plane-url http://127.0.0.1:7689
```

Terminal C (optional node agent):

```bash
export UNIKCTL_NODE_CONTROL_PLANE_URL=http://127.0.0.1:7689
export UNIKCTL_NODE_AGENT_NAME=wsl-node-1
export UNIKCTL_NODE_AGENT_ADVERTISE_URL=http://127.0.0.1:7780
unikctl node-agent
```

Then from Terminal B:

```bash
unikctl node list
unikctl node cordon wsl-node-1
unikctl node uncordon wsl-node-1
unikctl node drain wsl-node-1
```

## 9) What Files Are Created

In each app project directory:
- `.unikctl/native/rootfs/` (staged rootfs)
- `.unikraft/build/` (generated build artifacts, including initramfs)
- `unik.yaml` (may be auto-generated for native pipeline projects)

In runtime data dir (default):
- `~/.local/share/kraftkit/runtime/operations.db`
- `~/.local/share/kraftkit/runtime/workloads.db`
- `~/.local/share/kraftkit/runtime/nodes.db`
- `~/.local/share/kraftkit/runtime/services.db`
- `~/.local/share/kraftkit/runtime/jobs.db`
- `~/.local/share/kraftkit/runtime/warm_pool.db`

## 10) Clean Reset (Start Fresh)

Stop/destroy running apps first:

```bash
unikctl status
# destroy any running app names you see:
unikctl destroy <app-name>
```

Remove project-local artifacts:

```bash
find ~/apps/unikctl-tests -maxdepth 3 -type d \( -name .unikctl -o -name .unikraft \) -exec rm -rf {} +
```

Optional: clear runtime state DBs:

```bash
rm -rf ~/.local/share/kraftkit/runtime/operations.db \
       ~/.local/share/kraftkit/runtime/workloads.db \
       ~/.local/share/kraftkit/runtime/nodes.db \
       ~/.local/share/kraftkit/runtime/services.db \
       ~/.local/share/kraftkit/runtime/jobs.db \
       ~/.local/share/kraftkit/runtime/warm_pool.db
```

## 11) What Timing To Expect

Typical on first run:
- `build` may take 1-10+ minutes (dependency install + first rootfs)
- first `deploy` may take 30-180+ seconds (runtime pull + boot)

After cache warm-up:
- repeated deploys are usually much faster

Use these to inspect performance:

```bash
unikctl bench boot
unikctl bench density
unikctl substrate status
```

## 12) Final Validation Checklist

You are done when all are true:
- `unikctl doctor` has no blocking `FAIL`
- `unikctl build` succeeds for frontend and backend samples
- `unikctl deploy .` returns operation and launch URL
- `unikctl status` shows `running` for successful deploy operations
- `unikctl logs <app>` streams stdout logs
- `unikctl inspect <app>` shows runtime/resource/snapshot fields
- `unikctl destroy <app>` removes deployments
- `unikctl substrate status` and `unikctl bench *` commands return output
