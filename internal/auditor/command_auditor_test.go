package auditor

import "testing"

func TestIsAgentCLIProcess(t *testing.T) {
	t.Parallel()

	if !isAgentCLIProcess("claude-code") {
		t.Fatal("expected claude-code to be matched")
	}
	if !isAgentCLIProcess("gemini-cli") {
		t.Fatal("expected gemini-cli to be matched")
	}
	if isAgentCLIProcess("curl") {
		t.Fatal("did not expect curl to be matched")
	}
}

func TestExtractCommandCandidatesFromJSONClaude(t *testing.T) {
	t.Parallel()

	raw := `{
		"model":"claude-3-7-sonnet",
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","name":"bash","input":{"command":"python3 -c \"print('hi')\""}}]}
		]
	}`

	cands := extractCommandCandidatesFromJSON(raw)
	if len(cands) == 0 {
		t.Fatal("expected at least one command candidate")
	}
	want := "python3 -c \"print('hi')\""
	found := false
	for _, c := range cands {
		if c.Command == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected command %q in %#v", want, cands)
	}
}

func TestExtractCommandCandidatesFromJSONGemini(t *testing.T) {
	t.Parallel()

	raw := `{
		"tool":"run_shell_command",
		"arguments":{"shell_command":"ls -la && git status"}
	}`

	cands := extractCommandCandidatesFromJSON(raw)
	if len(cands) == 0 {
		t.Fatal("expected command candidate for gemini shell command")
	}
}

func TestExtractCommandCandidatesFromJSONNegative(t *testing.T) {
	t.Parallel()

	raw := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	cands := extractCommandCandidatesFromJSON(raw)
	if len(cands) != 0 {
		t.Fatalf("expected zero candidates, got %d", len(cands))
	}
}
