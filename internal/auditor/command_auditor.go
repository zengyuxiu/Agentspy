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

type CommandEventAuditor interface {
	AuditJSON(meta *pb.Event, rawJSON, channel string)
	AuditCommandEvent(evt ebpfcmd.CommandEvent)
}

type CommandAuditor struct {
	matcher ProviderMatcher
}

type commandCandidate struct {
	Tool    string
	Command string
	Path    string
}

func NewCommandAuditor(matcher ProviderMatcher) *CommandAuditor {
	if matcher == nil {
		matcher = NewProviderRegistry()
	}
	return &CommandAuditor{matcher: matcher}
}

func (c *CommandAuditor) AuditJSON(meta *pb.Event, rawJSON, channel string) {
	if !c.matcher.MatchesAgentProcess(meta.Pname) {
		return
	}

	candidates := extractCommandCandidatesFromJSONWithMatcher(rawJSON, c.matcher)
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
	if !c.matcher.MatchesAgentProcess(actor) && !c.matcher.MatchesAgentProcess(evt.ParentPname) {
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

func extractCommandCandidatesFromJSON(raw string) []commandCandidate {
	return extractCommandCandidatesFromJSONWithMatcher(raw, defaultProviderRegistry)
}

func extractCommandCandidatesFromJSONWithMatcher(raw string, matcher ProviderMatcher) []commandCandidate {
	if matcher == nil {
		matcher = defaultProviderRegistry
	}
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
	walkJSONForCommands(root, "", "", matcher, &out, seen)
	return out
}

func walkJSONForCommands(v any, path, tool string, matcher ProviderMatcher, out *[]commandCandidate, seen map[string]struct{}) {
	switch cur := v.(type) {
	case map[string]any:
		currentTool := tool
		if name, ok := cur["name"].(string); ok && matcher.MatchesCommandTool(name) {
			currentTool = name
		}
		if toolName, ok := cur["tool"].(string); ok && matcher.MatchesCommandTool(toolName) {
			currentTool = toolName
		}

		for k, child := range cur {
			nextPath := appendPath(path, k)
			if s, ok := child.(string); ok {
				if (matcher.MatchesCommandField(k) || matcher.MatchesCommandTool(currentTool)) && looksLikeShellOrPythonCommand(s) {
					addCandidate(out, seen, commandCandidate{
						Tool:    currentTool,
						Command: strings.TrimSpace(s),
						Path:    nextPath,
					})
				}
				continue
			}
			walkJSONForCommands(child, nextPath, currentTool, matcher, out, seen)
		}
	case []any:
		for i, item := range cur {
			walkJSONForCommands(item, appendPath(path, "["+intToString(i)+"]"), tool, matcher, out, seen)
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
