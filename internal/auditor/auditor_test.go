package auditor

import (
	"testing"

	"xiu.zyx/agentspy/internal/ebpfcmd"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

func TestIsLikelyLLMRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{
			name:    "chat_completions_messages",
			payload: "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[]}",
			want:    true,
		},
		{
			name:    "responses_prompt",
			payload: "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4.1\",\"prompt\":\"hello\"}",
			want:    true,
		},
		{
			name:    "non_post",
			payload: "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
			want:    false,
		},
		{
			name:    "post_but_unrelated",
			payload: "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n{\"file\":\"a.txt\"}",
			want:    false,
		},
		{
			name:    "openclaw_post",
			payload: "POST /v1/openclaw/execute HTTP/1.1\r\nHost: api.openclaw.ai\r\n\r\n{\"input\":\"hi\"}",
			want:    true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isLikelyLLMRequest(tc.payload)
			if got != tc.want {
				t.Fatalf("isLikelyLLMRequest() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExtractJSONBody(t *testing.T) {
	t.Parallel()

	payload := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n {\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"
	body, ok := extractJSONBody(payload)
	if !ok {
		t.Fatal("extractJSONBody() should succeed")
	}
	if body == "" || body[0] != '{' {
		t.Fatalf("extractJSONBody() returned invalid body: %q", body)
	}

	_, ok = extractJSONBody("POST /x HTTP/1.1\r\n\r\nplain text")
	if ok {
		t.Fatal("extractJSONBody() should fail when no JSON object exists")
	}
}

func TestContainsSensitiveContent(t *testing.T) {
	t.Parallel()

	if !containsSensitiveContent("my API_KEY is abc") {
		t.Fatal("expected API_KEY to be sensitive")
	}
	if !containsSensitiveContent("sk-abc123") {
		t.Fatal("expected sk- token to be sensitive")
	}
	if containsSensitiveContent("hello world") {
		t.Fatal("did not expect non-sensitive text to match")
	}
}

func TestPreview(t *testing.T) {
	t.Parallel()

	if got := preview("hello", 10); got != "hello" {
		t.Fatalf("preview() unexpected result: %q", got)
	}

	got := preview("1234567890", 5)
	if got != "12345...(truncated)" {
		t.Fatalf("preview() unexpected truncate result: %q", got)
	}
}

func TestSSEParserFeedSplitChunks(t *testing.T) {
	t.Parallel()

	state := &sseParserState{}
	out := state.feed("data: {\"choices\":[{\"delta\":{\"content\":\"Hel")
	if len(out) != 0 {
		t.Fatalf("expected no complete event yet, got %d", len(out))
	}

	out = state.feed("lo\"}}]}\n\n")
	if len(out) != 1 {
		t.Fatalf("expected one event, got %d", len(out))
	}

	got := extractSSEContent(out[0])
	if got != "Hello" {
		t.Fatalf("extractSSEContent() = %q, want %q", got, "Hello")
	}
}

func TestSSEParserFeedDoneAcrossChunks(t *testing.T) {
	t.Parallel()

	state := &sseParserState{}
	out := state.feed("data: [DO")
	if len(out) != 0 {
		t.Fatalf("expected no event, got %d", len(out))
	}

	out = state.feed("NE]\n\n")
	if len(out) != 1 || out[0] != "[DONE]" {
		t.Fatalf("expected [DONE], got %#v", out)
	}
}

func TestHandleEventHTTP1SSEDoneCleansState(t *testing.T) {
	t.Parallel()

	a := NewAuditor()
	evt := &pb.Event{
		Type:    3,
		Uuid:    "stream-http1-1",
		Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: [DONE]\n\n"),
	}
	a.HandleEvent(evt)

	a.mu.Lock()
	_, ok := a.sseStreams[evt.Uuid]
	a.mu.Unlock()
	if ok {
		t.Fatalf("expected stream state to be removed for uuid=%s", evt.Uuid)
	}
}

type spyCommandEventAuditor struct {
	jsonCalls int
}

func (s *spyCommandEventAuditor) AuditJSON(_ *pb.Event, _ string, _ string) {
	s.jsonCalls++
}

func (s *spyCommandEventAuditor) AuditCommandEvent(_ ebpfcmd.CommandEvent) {}

func TestAuditorWithInjectedProviderMatcher(t *testing.T) {
	t.Parallel()

	spy := &spyCommandEventAuditor{}
	a := NewAuditor(
		WithProviderMatcher(NewProviderRegistry(NewOpenClawAuditProvider())),
		WithCommandEventAuditor(spy),
	)

	nonOpenclawEvt := &pb.Event{
		Type:    1,
		Pname:   "openclaw-cli",
		Payload: []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[]}"),
	}
	a.HandleEvent(nonOpenclawEvt)
	if spy.jsonCalls != 0 {
		t.Fatalf("expected zero command-audit json calls for non-openclaw payload, got %d", spy.jsonCalls)
	}

	openclawEvt := &pb.Event{
		Type:    1,
		Pname:   "openclaw-cli",
		Payload: []byte("POST /v1/openclaw/execute HTTP/1.1\r\nHost: api.openclaw.ai\r\n\r\n{\"input\":\"hi\"}"),
	}
	a.HandleEvent(openclawEvt)
	if spy.jsonCalls != 1 {
		t.Fatalf("expected one command-audit json call for openclaw payload, got %d", spy.jsonCalls)
	}
}
