package auditor

import "strings"

// ProviderMatcher 定义统一规则接口，用于注入不同审计提供者规则。
type ProviderMatcher interface {
	MatchesAgentProcess(processName string) bool
	MatchesLLMRequestPayload(payload string) bool
	MatchesCommandTool(toolName string) bool
	MatchesCommandField(fieldName string) bool
}

// AuditProvider 定义单个提供者规则（Claude/Gemini/OpenClaw等）。
type AuditProvider interface {
	ProviderMatcher
	Name() string
}

type keywordProvider struct {
	name               string
	agentProcessKeys   []string
	llmPayloadKeys     []string
	commandToolKeys    []string
	commandFieldEquals []string
}

func (p keywordProvider) Name() string {
	return p.name
}

func (p keywordProvider) MatchesAgentProcess(processName string) bool {
	return containsAnyFold(processName, p.agentProcessKeys)
}

func (p keywordProvider) MatchesLLMRequestPayload(payload string) bool {
	return containsAnyFold(payload, p.llmPayloadKeys)
}

func (p keywordProvider) MatchesCommandTool(toolName string) bool {
	return equalsAnyFold(toolName, p.commandToolKeys)
}

func (p keywordProvider) MatchesCommandField(fieldName string) bool {
	k := strings.ToLower(strings.TrimSpace(fieldName))
	if k == "" {
		return false
	}
	for _, f := range p.commandFieldEquals {
		if k == f {
			return true
		}
	}
	return false
}

// ProviderRegistry 聚合多个审计提供者，实现统一匹配接口。
type ProviderRegistry struct {
	providers []AuditProvider
}

func NewProviderRegistry(providers ...AuditProvider) *ProviderRegistry {
	if len(providers) == 0 {
		providers = DefaultAuditProviders()
	}
	return &ProviderRegistry{providers: append([]AuditProvider(nil), providers...)}
}

func (r *ProviderRegistry) MatchesAgentProcess(processName string) bool {
	for _, p := range r.providers {
		if p.MatchesAgentProcess(processName) {
			return true
		}
	}
	return false
}

func (r *ProviderRegistry) MatchesLLMRequestPayload(payload string) bool {
	for _, p := range r.providers {
		if p.MatchesLLMRequestPayload(payload) {
			return true
		}
	}
	return false
}

func (r *ProviderRegistry) MatchesCommandTool(toolName string) bool {
	for _, p := range r.providers {
		if p.MatchesCommandTool(toolName) {
			return true
		}
	}
	return false
}

func (r *ProviderRegistry) MatchesCommandField(fieldName string) bool {
	for _, p := range r.providers {
		if p.MatchesCommandField(fieldName) {
			return true
		}
	}
	return false
}

func DefaultAuditProviders() []AuditProvider {
	return []AuditProvider{
		NewCommonAuditProvider(),
		NewClaudeCodeAuditProvider(),
		NewGeminiAuditProvider(),
		NewOpenClawAuditProvider(),
	}
}

func NewCommonAuditProvider() AuditProvider {
	return keywordProvider{
		name: "common",
		llmPayloadKeys: []string{
			`"messages"`,
			`"prompt"`,
			"/chat/completions",
			"/responses",
		},
		commandToolKeys: []string{
			"bash", "shell", "sh", "zsh", "terminal", "python",
		},
		commandFieldEquals: []string{
			"command", "cmd", "shell_command", "bash_command",
			"python_command", "python_code", "code", "script",
		},
	}
}

func NewClaudeCodeAuditProvider() AuditProvider {
	return keywordProvider{
		name: "claude-code",
		agentProcessKeys: []string{
			"claude", "claude-code",
		},
	}
}

func NewGeminiAuditProvider() AuditProvider {
	return keywordProvider{
		name: "gemini",
		agentProcessKeys: []string{
			"gemini", "gemini-cli",
		},
		commandToolKeys: []string{
			"run_shell_command", "execute_command", "execute_python", "run_python",
		},
	}
}

func NewOpenClawAuditProvider() AuditProvider {
	return keywordProvider{
		name: "openclaw",
		agentProcessKeys: []string{
			"openclaw", "openclaw-cli",
		},
		llmPayloadKeys: []string{
			"openclaw",
			"/v1/openclaw/execute",
		},
		commandToolKeys: []string{
			"openclaw_shell", "openclaw_command",
		},
		commandFieldEquals: []string{
			"openclaw_command",
		},
	}
}

var defaultProviderRegistry ProviderMatcher = NewProviderRegistry()

func isAgentCLIProcess(pname string) bool {
	return defaultProviderRegistry.MatchesAgentProcess(pname)
}

func isLikelyLLMRequestPayload(payload string) bool {
	return defaultProviderRegistry.MatchesLLMRequestPayload(payload)
}

func isLikelyCommandTool(name string) bool {
	return defaultProviderRegistry.MatchesCommandTool(name)
}

func isCommandField(key string) bool {
	return defaultProviderRegistry.MatchesCommandField(key)
}

func containsAnyFold(text string, keywords []string) bool {
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return false
	}
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func equalsAnyFold(text string, keywords []string) bool {
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return false
	}
	for _, k := range keywords {
		if s == strings.ToLower(strings.TrimSpace(k)) {
			return true
		}
	}
	return false
}
