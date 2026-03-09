package auditor

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"xiu.zyx/agentspy/internal/ebpfcmd"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

type CommandAuditor struct{}

type commandCandidate struct {
	Tool    string
	Command string
	Path    string
}

func NewCommandAuditor() *CommandAuditor {
	return &CommandAuditor{}
}

func (c *CommandAuditor) AuditJSON(meta *pb.Event, rawJSON, channel string) {
	if !isAgentCLIProcess(meta.Pname) {
		return
	}

	candidates := extractCommandCandidatesFromJSON(rawJSON)
	if len(candidates) == 0 {
		return
	}

	timestamp := time.Unix(0, meta.Timestamp).Format(time.RFC3339)
	for _, cand := range candidates {
		level := "[CMD-AUDIT]"
		if isDangerousCommand(cand.Command) {
			level = "[CRITICAL]"
		}
		log.Printf("%s %s | PID:%d (%s) | %s | Tool:%s | Path:%s | Cmd:%s",
			level, timestamp, meta.Pid, meta.Pname, channel, defaultValue(cand.Tool, "unknown"),
			cand.Path, preview(cand.Command, 160))
	}
}

func (c *CommandAuditor) AuditCommandEvent(evt ebpfcmd.CommandEvent) {
	actor := defaultValue(evt.Pname, "unknown")
	if !isAgentCLIProcess(actor) && !isAgentCLIProcess(evt.ParentPname) {
		return
	}

	level := "[CMD-AUDIT]"
	if isDangerousCommand(evt.Command) {
		level = "[CRITICAL]"
	}

	timestamp := time.Unix(0, evt.Timestamp).Format(time.RFC3339)
	if evt.Timestamp <= 0 {
		timestamp = time.Now().Format(time.RFC3339)
	}
	log.Printf("%s %s | PID:%d (%s) | ebpf | Parent:%s | Source:%s | Cmd:%s",
		level, timestamp, evt.Pid, actor, defaultValue(evt.ParentPname, "unknown"),
		defaultValue(evt.Source, "ebpf"), preview(evt.Command, 160))
}

func isAgentCLIProcess(pname string) bool {
	p := strings.ToLower(pname)
	targets := []string{
		"claude", "claude-code", "gemini", "gemini-cli",
	}
	for _, t := range targets {
		if strings.Contains(p, t) {
			return true
		}
	}
	return false
}

func extractCommandCandidatesFromJSON(raw string) []commandCandidate {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "{") {
		return nil
	}

	var root any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil
	}

	out := make([]commandCandidate, 0, 4)
	seen := make(map[string]struct{})
	walkJSONForCommands(root, "", "", &out, seen)
	return out
}

func walkJSONForCommands(v any, path, tool string, out *[]commandCandidate, seen map[string]struct{}) {
	switch cur := v.(type) {
	case map[string]any:
		currentTool := tool
		if name, ok := cur["name"].(string); ok && isLikelyCommandTool(name) {
			currentTool = name
		}
		if toolName, ok := cur["tool"].(string); ok && isLikelyCommandTool(toolName) {
			currentTool = toolName
		}

		for k, child := range cur {
			nextPath := appendPath(path, k)
			if s, ok := child.(string); ok {
				if (isCommandField(k) || isLikelyCommandTool(currentTool)) && looksLikeShellOrPythonCommand(s) {
					addCandidate(out, seen, commandCandidate{
						Tool:    currentTool,
						Command: strings.TrimSpace(s),
						Path:    nextPath,
					})
				}
				continue
			}
			walkJSONForCommands(child, nextPath, currentTool, out, seen)
		}
	case []any:
		for i, item := range cur {
			walkJSONForCommands(item, appendPath(path, "["+intToString(i)+"]"), tool, out, seen)
		}
	}
}

func addCandidate(out *[]commandCandidate, seen map[string]struct{}, c commandCandidate) {
	key := c.Tool + "|" + c.Path + "|" + c.Command
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, c)
}

func appendPath(base, next string) string {
	if base == "" {
		return next
	}
	if strings.HasPrefix(next, "[") {
		return base + next
	}
	return base + "." + next
}

func intToString(i int) string {
	return strconv.Itoa(i)
}

func isLikelyCommandTool(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	tools := []string{
		"bash", "shell", "sh", "zsh", "terminal", "python",
		"run_shell_command", "execute_command", "execute_python", "run_python",
	}
	for _, t := range tools {
		if strings.Contains(n, t) {
			return true
		}
	}
	return false
}

func isCommandField(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	fields := []string{
		"command", "cmd", "shell_command", "bash_command",
		"python_command", "python_code", "code", "script",
	}
	for _, f := range fields {
		if k == f {
			return true
		}
	}
	return false
}

func looksLikeShellOrPythonCommand(text string) bool {
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return false
	}

	prefixes := []string{
		"python ", "python3 ", "python -c ", "python3 -c ",
		"bash -c ", "sh -c ", "zsh -c ",
		"pip ", "pip3 ", "uv run ", "uvx ",
		"ls ", "cat ", "grep ", "find ", "sed ", "awk ",
		"curl ", "wget ", "git ", "go ", "npm ", "pnpm ", "yarn ",
		"docker ", "kubectl ", "chmod ", "chown ", "mkdir ", "rm ", "cp ", "mv ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}

	return strings.Contains(s, " && ") || strings.Contains(s, " | ") || strings.Contains(s, "; ")
}

func isDangerousCommand(cmd string) bool {
	s := strings.ToLower(cmd)
	rules := []string{
		"rm -rf /", "rm -rf ~", "mkfs", "dd if=", ":(){:|:&};:",
		"| sh", "| bash", "chmod 777",
	}
	for _, r := range rules {
		if strings.Contains(s, r) {
			return true
		}
	}
	return false
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
