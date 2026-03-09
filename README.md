# Agentspy

Agentspy is an auditing tool for AI agent workflows, focused on:

- LLM traffic auditing from eCapture WebSocket events
- Command execution auditing (Claude Code / Gemini CLI) via eBPF

Chinese documentation is available in [README.zh.md](./README.zh.md).

## Features

- Audits HTTP/1.x and HTTP/2 requests/responses (with SSE stream reassembly)
- Detects sensitive content (`password`, `token`, `sk-`, etc.)
- Audits shell/python commands triggered by agent tool calls
- Runs SSL audit and command eBPF audit as parallel modules
- Uses `bpf2go` embedded BPF objects (no external userspace helper binary required)

## Project Layout

```text
cmd/agentspy/              # App entrypoint
internal/client/           # eCapture WS client (SSL/TLS audit pipeline)
internal/auditor/          # LLM + command audit logic
internal/ebpfcmd/          # eBPF command audit module (bpf2go loader)
internal/config/           # config.yaml loader/defaults
bpf/claude_cmd.bpf.c       # eBPF C program
config.yaml                # Runtime config
```

## Requirements

- Go 1.25+
- clang/llvm (for `bpf2go`)
- Linux kernel with eBPF support (for command audit module)
- Running eCapture service (for SSL audit module)

## Configuration

Edit [config.yaml](./config.yaml):

```yaml
ssl:
  enabled: true
  ws_addr: "127.0.0.1:28257"
  ws_origin: "http://localhost/"
  retry_interval: "5s"

command_ebpf:
  enabled: false
  claude_bin: ""
```

Notes:

- If `command_ebpf.claude_bin` is empty, Agentspy auto-discovers the binary using:
  - `whereis -b claude bun claude-code`
  - fallback: `PATH` lookup
- The uprobe symbol is fixed to `uv_spawn`.

## Build and Run

1. Generate eBPF bindings (first time, or after changing `bpf/*.bpf.c`):

```bash
go generate ./internal/ebpfcmd
```

2. Run:

```bash
go run ./cmd/agentspy -config ./config.yaml
```

## Docker Compose Deployment

The compose stack includes:

- `ecapture` (equivalent to your `docker run` command)
- `agentspy`

Start:

```bash
docker compose up -d --build
```

Stop:

```bash
docker compose down
```

The `ecapture` service runs with:

- `privileged: true`
- `network_mode: host`
- `/lib/modules` and `/usr/src` mounted read-only
- command: `tls --ecaptureq=ws://127.0.0.1:28257/`

Agentspy uses host networking and reads runtime config from `./config.yaml`.

## Modes

- SSL only: `ssl.enabled=true`, `command_ebpf.enabled=false`
- Command eBPF only: `ssl.enabled=false`, `command_ebpf.enabled=true`
- Both modules: set both `enabled=true`

## Testing

```bash
go test ./...
```

## Notes

- eBPF attachment typically requires root privileges.
- On some kernels, syscall symbol names may vary; tracepoints can be used as fallback.
- If auto-discovery fails, set `command_ebpf.claude_bin` explicitly.
