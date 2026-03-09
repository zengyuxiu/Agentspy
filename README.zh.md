# Agentspy

`Agentspy` 是一个面向 AI Agent 场景的审计工具，聚焦两类行为：

- LLM 网络调用审计（基于 eCapture WebSocket 事件流）
- Claude Code / Gemini CLI 命令执行审计（基于 eBPF）

项目目标是对“提示词与流式输出中的敏感信息”和“Agent 发起的 shell/python 命令”进行实时检测与告警。

## 功能特性

- 审计 HTTP/1.x 与 HTTP/2 请求/响应（含 SSE 流式分片重组）
- 检测敏感内容（如 `password`、`token`、`sk-` 等）
- 识别 Claude/Gemini 相关命令调用并输出命令审计日志
- 命令审计模块与 SSL 审计模块并列运行，互不耦合
- eBPF 使用 `bpf2go` 内嵌加载，无需外挂 userspace 可执行文件

## 目录结构

```text
cmd/agentspy/              # 程序入口
internal/client/           # eCapture WS 客户端（SSL/TLS审计链路）
internal/auditor/          # LLM审计 + 命令审计核心逻辑
internal/ebpfcmd/          # eBPF命令审计模块（bpf2go对象加载）
internal/config/           # config.yaml 读取与默认值
bpf/claude_cmd.bpf.c       # eBPF C 程序
config.yaml                # 运行配置
```

## 依赖

- Go 1.25+
- clang/llvm（用于 `bpf2go`）
- Linux 内核支持 eBPF（命令审计模块需要）
- 已运行的 eCapture 服务（用于 SSL 审计模块）

## 配置

编辑 [config.yaml](./config.yaml)：

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

说明：

- `command_ebpf.claude_bin` 为空时，程序会优先通过 `whereis -b claude bun claude-code` 自动定位二进制路径。
- `uv_spawn` 符号已在代码中写死，不需要额外配置。

## 构建与运行

1. 生成 eBPF 绑定代码（首次或修改 `bpf/*.bpf.c` 后执行）

```bash
go generate ./internal/ebpfcmd
```

2. 启动程序

```bash
go run ./cmd/agentspy -config ./config.yaml
```

## 运行模式

- 仅 SSL 审计：`ssl.enabled=true`，`command_ebpf.enabled=false`
- 仅命令审计：`ssl.enabled=false`，`command_ebpf.enabled=true`
- 双模块并行：两者都设为 `true`

## 日志示例

- LLM 请求审计：
  - `[AUDIT] ... | LLM Access | Model: ... | Prompt Len: ...`
- 敏感信息告警：
  - `[CRITICAL] ... | LEAK DETECTED | Content: ...`
- 命令审计：
  - `[CMD-AUDIT] ... | ebpf | Source:uv_spawn | Cmd: ...`

## 测试

```bash
go test ./...
```

## 注意事项

- 命令审计依赖 eBPF 挂载，通常需要 root 权限运行。
- 不同发行版/内核下 `execve` 符号可见性可能不同，必要时可改为 tracepoint 方案。
- `whereis` 找不到目标二进制时，请在 `config.yaml` 显式设置 `command_ebpf.claude_bin`。
