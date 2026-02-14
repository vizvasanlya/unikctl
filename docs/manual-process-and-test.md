# unikctl Manual Process and Test Guide

This guide gives a full manual flow to process, run, and verify `unikctl` end-to-end.

## 1) Prerequisites

Host requirements:

- 64-bit Go installed (`go version`)
- Unikernel runtime dependencies for your platform (QEMU/Firecracker as needed)
- Language toolchain for your app (`go`, `python`, `node`, etc.)
- No Docker required

Quick checks:

```powershell
go version
qemu-system-x86_64 --version
```

## 2) Build `unikctl` from source

From repo root (`unikctl-rebrand`):

```powershell
go build -o .\unikctl.exe .\cmd\unikctl
.\unikctl.exe --help
```

Expected top-level commands:

- `build`
- `deploy`
- `logs`
- `status`
- `destroy`
- `doctor`
- `migrate`
- `node` (list/cordon/uncordon/drain)

Run diagnostics:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe doctor
```

## 3) Create a minimal test app

### Option A: Go app (recommended first test)

Create `D:\tmp\unik-go\main.go`:

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello from unikctl")
	})
	fmt.Println("server starting on :8080")
	_ = http.ListenAndServe(":8080", nil)
}
```

### Option B: Python app

Create `D:\tmp\unik-py\app.py`:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello from unikctl python")

print("server starting on :8080")
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
```

## 4) Test local mode first

Run from your app directory (example uses Go app):

```powershell
cd D:\tmp\unik-go
D:\kernel\unikctl-rebrand\unikctl.exe build
D:\kernel\unikctl-rebrand\unikctl.exe deploy .
D:\kernel\unikctl-rebrand\unikctl.exe status
```

`deploy .` auto-builds source directories before selecting the runtime runner.

Get machine name from `status`, then:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe logs <machine-name>
D:\kernel\unikctl-rebrand\unikctl.exe destroy <machine-name>
```

## 4.1) Test Docker migration path

From a project with Dockerfile:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe migrate dockerfile .
```

From a project with docker-compose:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe migrate compose .\docker-compose.yml
```

Expected:

- `unik.yaml` (or `unik.migrated.yaml`) is generated per Dockerfile migration
- `unikctl-compose.migrated.yaml` is generated for compose migration
- generated plan contains per-service `unikctl deploy ...` commands

## 5) Test debug vs release build modes

Release (default):

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe build
```

Debug:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe build --debug
```

Validate:

- `--debug` should produce symbolic/debug-friendly artifacts.
- `deploy --debug .` should use debug path in deploy flow.

## 6) Test control-plane mode (remote API path)

Open terminal A (server):

```powershell
cd D:\kernel\unikctl-rebrand
$env:UNIKCTL_CONTROL_PLANE_LISTEN="127.0.0.1:7689"
.\unikctl.exe control-plane
```

Open terminal B (client):

```powershell
$env:UNIKCTL_CONTROL_PLANE_URL="http://127.0.0.1:7689"
cd D:\tmp\unik-go
D:\kernel\unikctl-rebrand\unikctl.exe deploy .
```

Open terminal C (node agent on a worker host):

```powershell
$env:UNIKCTL_NODE_CONTROL_PLANE_URL="http://127.0.0.1:7689"
$env:UNIKCTL_NODE_CONTROL_PLANE_TOKEN="change-me"
$env:UNIKCTL_NODE_AGENT_TOKEN="node-agent-secret"
$env:UNIKCTL_NODE_AGENT_ADVERTISE_URL="http://127.0.0.1:7780"
$env:UNIKCTL_NODE_AGENT_LABELS="zone=local,tier=general"
D:\kernel\unikctl-rebrand\unikctl.exe node-agent
```

Optional auth/TLS:

```powershell
$env:UNIKCTL_CONTROL_PLANE_TOKEN="change-me"
$env:UNIKCTL_CONTROL_PLANE_RBAC_TOKENS="change-me=*;ops-token=status,logs"
$env:UNIKCTL_CONTROL_PLANE_JWT_HS256_SECRET="replace-with-strong-secret"
$env:UNIKCTL_CONTROL_PLANE_TLS_CERT_FILE="D:\certs\cp.crt"
$env:UNIKCTL_CONTROL_PLANE_TLS_KEY_FILE="D:\certs\cp.key"
```

Expected:

- CLI prints `uploading source artifact to control plane...`
- CLI prints `uploading rootfs artifact to control plane...` when `--rootfs` is a local client path
- CLI returns `operation: op-...`

Then:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe status
D:\kernel\unikctl-rebrand\unikctl.exe node list
D:\kernel\unikctl-rebrand\unikctl.exe logs <machine-name>
D:\kernel\unikctl-rebrand\unikctl.exe destroy <machine-name>
```

Node maintenance test:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe node cordon <node-name>
D:\kernel\unikctl-rebrand\unikctl.exe node drain <node-name>
D:\kernel\unikctl-rebrand\unikctl.exe node uncordon <node-name>
```

Rootfs artifact parity check:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe deploy --rootfs . .
```

## 7) API-level smoke checks (optional)

```powershell
curl http://127.0.0.1:7689/healthz
curl http://127.0.0.1:7689/v1/status
curl http://127.0.0.1:7689/v1/metrics
curl -X POST http://127.0.0.1:7689/v1/nodes/my-node/cordon -H "Authorization: Bearer change-me"
```

## 8) Negative tests (important)

Run these and confirm they fail cleanly:

- Invalid deploy path:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe deploy D:\tmp\does-not-exist
```

- Invalid destroy request:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe destroy
```

- Dockerfile rootfs rejected:

```powershell
D:\kernel\unikctl-rebrand\unikctl.exe build --rootfs .\Dockerfile
```

## 9) Where runtime data is stored

Operation history and control-plane artifacts are stored under the configured runtime dir (from `config`), including:

- operation journal (`operations.json`)
- control-plane uploaded source/rootfs artifacts
- durable queued job records (`control-plane-jobs/*.json`)

Use `status` as the primary operational view.

## 10) Linux command equivalents

Build:

```bash
go build -o ./unikctl ./cmd/unikctl
./unikctl --help
```

Control-plane server:

```bash
UNIKCTL_CONTROL_PLANE_LISTEN=127.0.0.1:7689 ./unikctl control-plane
```

Client remote mode:

```bash
export UNIKCTL_CONTROL_PLANE_URL=http://127.0.0.1:7689
./unikctl deploy .
./unikctl status
./unikctl logs <machine-name>
./unikctl destroy <machine-name>
```

Benchmark harness:

```bash
go build -o ./unikctl ./cmd/unikctl
go run ./tools/benchharness --binary ./unikctl --iterations 3
```

## 11) Troubleshooting

- `could not determine how to run provided input`
  - Ensure app directory has expected files (`go.mod`, `package.json`, `requirements.txt`, etc.) or add `unik.yaml`.
- `qemu not found` or hypervisor errors
  - Install/configure the required VMM for your platform.
- Upload works but deploy fails later
  - Artifact transfer is correct; inspect `status` message and `logs` for runner/runtime issue.
- `unsupported platform driver` on local Windows host
  - Use control-plane mode on a Linux host and point your client with `UNIKCTL_CONTROL_PLANE_URL`.

## 12) Completion checklist

You are done when all are true:

- `build` works in release mode
- `build --debug` works
- `deploy` returns operation ID
- `status` shows operation lifecycle
- `status` shows launch `SERVICE`, `PUBLIC PORT`, and `URL` for mapped web ports
- `logs` streams stdout output
- `destroy` removes machine
- Control-plane remote deploy shows artifact upload line and executes via API
- `doctor` reports host readiness
- control-plane `/v1/metrics` endpoint is reachable
- node-agent registration + heartbeat updates `node list`
- cordon/drain/uncordon commands return successful node state transitions
- benchmark harness writes `benchmark-results.json` and `benchmark-metrics.txt`
