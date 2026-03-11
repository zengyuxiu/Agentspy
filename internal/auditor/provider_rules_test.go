package auditor

import "testing"

func TestProviderRegistryProcessIsolation(t *testing.T) {
	t.Parallel()

	claudeOnly := NewProviderRegistry(NewClaudeCodeAuditProvider())
	if !claudeOnly.MatchesAgentProcess("claude-code") {
		t.Fatal("expected claude-only registry to match claude-code")
	}
	if claudeOnly.MatchesAgentProcess("openclaw-cli") {
		t.Fatal("did not expect claude-only registry to match openclaw-cli")
	}

	openclawOnly := NewProviderRegistry(NewOpenClawAuditProvider())
	if !openclawOnly.MatchesAgentProcess("openclaw-cli") {
		t.Fatal("expected openclaw-only registry to match openclaw-cli")
	}
	if openclawOnly.MatchesAgentProcess("claude-code") {
		t.Fatal("did not expect openclaw-only registry to match claude-code")
	}
}

func TestProviderRegistryLLMRequestIsolation(t *testing.T) {
	t.Parallel()

	openclawOnly := NewProviderRegistry(NewOpenClawAuditProvider())
	if !openclawOnly.MatchesLLMRequestPayload("/v1/openclaw/execute") {
		t.Fatal("expected openclaw request to be matched")
	}
	if openclawOnly.MatchesLLMRequestPayload("/v1/chat/completions") {
		t.Fatal("did not expect openclaw-only registry to match generic chat/completions")
	}
}
