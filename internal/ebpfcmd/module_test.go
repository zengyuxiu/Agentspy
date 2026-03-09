package ebpfcmd

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestJoinCommandParts(t *testing.T) {
	t.Parallel()

	got := joinCommandParts("/bin/bash", "bash", "-lc")
	if got != "/bin/bash bash -lc" {
		t.Fatalf("unexpected command: %q", got)
	}
}

func TestCString(t *testing.T) {
	t.Parallel()

	buf := [8]byte{'u', 'v', '_', 's', 'p', 'a', 'w', 'n'}
	got := cString(buf[:])
	if got != "uv_spawn" {
		t.Fatalf("unexpected cstring: %q", got)
	}
}

func TestDecodeBPFEvent(t *testing.T) {
	t.Parallel()

	var evt bpfEvent
	evt.TsNs = 123
	evt.Tgid = 456
	copyInt8(evt.Source[:], "uv_spawn")
	copyInt8(evt.Comm[:], "claude-code")
	copyInt8(evt.File[:], "/bin/bash")
	copyInt8(evt.Arg0[:], "bash")
	copyInt8(evt.Arg1[:], "-lc")

	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, evt); err != nil {
		t.Fatalf("binary.Write() error: %v", err)
	}

	out, ok := decodeBPFEvent(raw.Bytes())
	if !ok {
		t.Fatal("expected decode success")
	}
	if out.Pid != 456 {
		t.Fatalf("unexpected pid: %d", out.Pid)
	}
	if out.Pname != "claude-code" {
		t.Fatalf("unexpected pname: %q", out.Pname)
	}
	if out.Source != "uv_spawn" {
		t.Fatalf("unexpected source: %q", out.Source)
	}
	if out.Command != "/bin/bash bash -lc" {
		t.Fatalf("unexpected command: %q", out.Command)
	}
}

func TestParseWhereisOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write temp bin failed: %v", err)
	}

	out := "claude: " + bin + "\n" + "bun:\n"
	got, ok := parseWhereisOutput(out)
	if !ok {
		t.Fatal("expected parseWhereisOutput success")
	}
	if got != bin {
		t.Fatalf("unexpected path: %s", got)
	}
}

func copyInt8(dst []byte, s string) {
	for i := 0; i < len(dst) && i < len(s); i++ {
		dst[i] = s[i]
	}
}
