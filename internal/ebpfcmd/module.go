package ebpfcmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const uprobeSymbol = "uv_spawn"

type bpfEvent struct {
	TsNs   uint64
	Pid    uint32
	Tgid   uint32
	Source [16]byte
	Comm   [16]byte
	File   [128]byte
	Arg0   [128]byte
	Arg1   [128]byte
}

type CommandEvent struct {
	Timestamp   int64
	Pid         int64
	Pname       string
	ParentPname string
	Command     string
	Source      string
}

type Config struct {
	Enabled       bool
	ClaudeBinPath string
}

type Module struct {
	cfg Config
}

func NewModule(cfg Config) *Module {
	return &Module{cfg: cfg}
}

func (m *Module) Start(ctx context.Context, sink func(CommandEvent)) error {
	if !m.cfg.Enabled {
		return nil
	}
	claudeBin, err := resolveClaudeBinary(m.cfg.ClaudeBinPath)
	if err != nil {
		return err
	}

	var objs claudeCmdObjects
	if err := loadClaudeCmdObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	exe, err := link.OpenExecutable(claudeBin)
	if err != nil {
		return fmt.Errorf("open executable %q: %w", claudeBin, err)
	}

	up, err := exe.Uprobe(uprobeSymbol, objs.UprobeUvSpawn, nil)
	if err != nil {
		return fmt.Errorf("attach uprobe %s: %w", uprobeSymbol, err)
	}
	defer up.Close()

	kpExecve, err := link.Kprobe("__x64_sys_execve", objs.KpExecve, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe execve: %w", err)
	}
	defer kpExecve.Close()

	kpExecveat, err := link.Kprobe("__x64_sys_execveat", objs.KpExecveat, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe execveat: %w", err)
	}
	defer kpExecveat.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rd.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		record, err := rd.Read()
		if err != nil {
			if isRingbufClosed(err) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		evt, ok := decodeBPFEvent(record.RawSample)
		if ok {
			sink(evt)
		}
	}
}

func resolveClaudeBinary(configured string) (string, error) {
	if p := strings.TrimSpace(configured); p != "" {
		return p, nil
	}

	// 1) Prefer whereis for deterministic system-level resolution.
	if path, ok := findByWhereis("claude", "bun", "claude-code"); ok {
		return path, nil
	}
	// 2) Fallback to PATH lookup.
	for _, name := range []string{"claude", "bun", "claude-code"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("cannot locate claude/bun binary; set command_ebpf.claude_bin in config.yaml")
}

func findByWhereis(names ...string) (string, bool) {
	args := append([]string{"-b"}, names...)
	out, err := exec.Command("whereis", args...).Output()
	if err != nil {
		return "", false
	}
	return parseWhereisOutput(string(out))
}

func parseWhereisOutput(out string) (string, bool) {
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, p := range fields[1:] {
			if strings.HasSuffix(p, ":") {
				continue
			}
			if abs, err := filepath.Abs(p); err == nil && isExecutable(abs) {
				return abs, true
			}
			if isExecutable(p) {
				return p, true
			}
		}
	}
	return "", false
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0111 != 0
}

func decodeBPFEvent(raw []byte) (CommandEvent, bool) {
	var e bpfEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return CommandEvent{}, false
	}

	source := cString(e.Source[:])
	file := cString(e.File[:])
	arg0 := cString(e.Arg0[:])
	arg1 := cString(e.Arg1[:])
	command := joinCommandParts(file, arg0, arg1)
	if command == "" {
		return CommandEvent{}, false
	}

	return CommandEvent{
		Timestamp: int64(e.TsNs),
		Pid:       int64(e.Tgid),
		Pname:     cString(e.Comm[:]),
		Command:   command,
		Source:    source,
	}, true
}

func joinCommandParts(file, arg0, arg1 string) string {
	parts := make([]string, 0, 3)
	if file != "" {
		parts = append(parts, file)
	}
	if arg0 != "" && arg0 != file {
		parts = append(parts, arg0)
	}
	if arg1 != "" {
		parts = append(parts, arg1)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func cString(buf []byte) string {
	out := make([]byte, 0, len(buf))
	for _, c := range buf {
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

func isRingbufClosed(err error) bool {
	return strings.Contains(err.Error(), "ringbuffer is closed")
}
