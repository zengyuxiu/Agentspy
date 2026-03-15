package ebpfcmd

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCString(t *testing.T) {
	t.Parallel()

	buf := [9]byte{'f', 'i', 'l', 'e', '_', 'r', 'e', 'a', 'd'}
	got := cString(buf[:])
	if got != "file_read" {
		t.Fatalf("unexpected cstring: %q", got)
	}
}

func TestDecodeBPFEvent(t *testing.T) {
	t.Parallel()

	var evt bpfEvent
	evt.TsNs = 123
	evt.Tgid = 456
	copyBytes(evt.Source[:], "execve")
	copyBytes(evt.Comm[:], "claude")
	copyBytes(evt.File[:], "/bin/bash")
	copyBytes(evt.Arg0[:], "bash")
	copyBytes(evt.Arg1[:], "-c")
	copyBytes(evt.Arg2[:], "cat /etc/passwd")

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
	if out.Pname != "claude" {
		t.Fatalf("unexpected pname: %q", out.Pname)
	}
	if out.Source != "execve" {
		t.Fatalf("unexpected source: %q", out.Source)
	}
	if out.Command != "cat /etc/passwd" {
		t.Fatalf("unexpected command: %q", out.Command)
	}
}

func TestDecodeBPFEventEmptyPath(t *testing.T) {
	t.Parallel()

	var evt bpfEvent
	evt.TsNs = 1
	evt.Tgid = 2
	copyBytes(evt.Source[:], "file_read")
	copyBytes(evt.Comm[:], "claude")

	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, evt); err != nil {
		t.Fatalf("binary.Write() error: %v", err)
	}

	_, ok := decodeBPFEvent(raw.Bytes())
	if ok {
		t.Fatal("expected decode failure for empty file path")
	}
}

func TestResolveCommandFileEvent(t *testing.T) {
	t.Parallel()

	got := resolveCommand("file_read", "/tmp/x", "", "", "")
	if got != "/tmp/x" {
		t.Fatalf("unexpected file command: %q", got)
	}
}

func TestResolveCommandExecveFallback(t *testing.T) {
	t.Parallel()

	got := resolveCommand("execve", "/usr/bin/git", "git", "status", "")
	if got != "/usr/bin/git git status" {
		t.Fatalf("unexpected fallback command: %q", got)
	}
}

func copyBytes(dst []byte, s string) {
	for i := 0; i < len(dst) && i < len(s); i++ {
		dst[i] = s[i]
	}
}
