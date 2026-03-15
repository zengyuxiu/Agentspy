package ebpfcmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type bpfEvent struct {
	TsNs   uint64
	Pid    uint32
	Tgid   uint32
	Source [16]byte
	Comm   [16]byte
	File   [256]byte
	Arg0   [128]byte
	Arg1   [128]byte
	Arg2   [256]byte
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
	if sink == nil {
		return fmt.Errorf("sink must not be nil")
	}

	var objs claudeCmdObjects
	if err := loadClaudeCmdObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_openat: %w", err)
	}
	defer tpOpenat.Close()

	tpOpenat2, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.TpOpenat2, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_openat2: %w", err)
	}
	defer tpOpenat2.Close()

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TpExecve, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_execve: %w", err)
	}
	defer tpExecve.Close()

	tpExecveat, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.TpExecveat, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_execveat: %w", err)
	}
	defer tpExecveat.Close()

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

func decodeBPFEvent(raw []byte) (CommandEvent, bool) {
	var e bpfEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return CommandEvent{}, false
	}

	file := cString(e.File[:])
	arg0 := cString(e.Arg0[:])
	arg1 := cString(e.Arg1[:])
	arg2 := cString(e.Arg2[:])
	source := cString(e.Source[:])

	command := resolveCommand(source, file, arg0, arg1, arg2)
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

func resolveCommand(source, file, arg0, arg1, arg2 string) string {
	switch source {
	case "file_read", "file_write", "file_rw":
		return strings.TrimSpace(file)
	case "execve":
		if shouldUnwrapShellCommand(file, arg0, arg1) && strings.TrimSpace(arg2) != "" {
			return strings.TrimSpace(arg2)
		}
		return joinExecCommand(file, arg0, arg1, arg2)
	default:
		if strings.TrimSpace(file) != "" {
			return strings.TrimSpace(file)
		}
		return joinExecCommand(file, arg0, arg1, arg2)
	}
}

func shouldUnwrapShellCommand(file, arg0, arg1 string) bool {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(file)))
	if name == "" {
		name = strings.ToLower(filepath.Base(strings.TrimSpace(arg0)))
	}
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "fish":
	default:
		return false
	}
	a1 := strings.TrimSpace(arg1)
	if !strings.HasPrefix(a1, "-") {
		return false
	}
	return strings.Contains(a1, "c")
}

func joinExecCommand(file, arg0, arg1, arg2 string) string {
	parts := make([]string, 0, 4)
	if s := strings.TrimSpace(file); s != "" {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(arg0); s != "" && s != strings.TrimSpace(file) {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(arg1); s != "" {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(arg2); s != "" {
		parts = append(parts, s)
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
