package auditor

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"xiu.zyx/agentspy/internal/ebpfcmd"

	// 引入协议定义
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
)

// LLMRequest 定义 OpenAI 风格的请求体
type LLMRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type Auditor struct {
	mu         sync.Mutex
	sseStreams map[string]*sseParserState
	cmdAuditor *CommandAuditor
}

type sseParserState struct {
	pendingLine string
	currentData []string
	lastSeen    time.Time
}

func NewAuditor() *Auditor {
	return &Auditor{
		sseStreams: make(map[string]*sseParserState),
		cmdAuditor: NewCommandAuditor(),
	}
}

// HandleEvent 处理具体的业务事件
func (a *Auditor) HandleEvent(event *pb.Event) {
	switch event.Type {
	case 1, 2:
		a.handleRequest(event)
	case 3, 4:
		a.handleResponseStream(event)
	default:
		return
	}
}

func (a *Auditor) HandleCommandEvent(event ebpfcmd.CommandEvent) {
	a.cmdAuditor.AuditCommandEvent(event)
}

func (a *Auditor) handleRequest(event *pb.Event) {
	payload := string(event.Payload)
	if payload == "" || !isLikelyLLMRequest(payload) {
		return
	}

	jsonBody, ok := extractJSONBody(payload)
	if !ok {
		return
	}
	var req LLMRequest
	if err := json.Unmarshal([]byte(jsonBody), &req); err == nil {
		a.auditLLMRequest(event, req)
	}
	a.cmdAuditor.AuditJSON(event, jsonBody, "request")
}

func (a *Auditor) handleResponseStream(event *pb.Event) {
	payload := string(event.Payload)
	if payload == "" || !isLikelySSEResponse(payload) {
		return
	}

	events := a.consumeSSEChunk(event.Uuid, payload)
	if len(events) == 0 {
		return
	}

	timestamp := time.Unix(0, event.Timestamp)
	for _, data := range events {
		if data == "[DONE]" {
			log.Printf("[STREAM]   %s | PID:%d (%s) | Stream Done | UUID:%s",
				timestamp.Format(time.RFC3339), event.Pid, event.Pname, event.Uuid)
			a.closeSSEStream(event.Uuid)
			continue
		}

		a.cmdAuditor.AuditJSON(event, data, "response_stream")
		content := extractSSEContent(data)
		if content != "" {
			if containsSensitiveContent(content) {
				log.Printf("[CRITICAL] %s | PID:%d (%s) | STREAM LEAK | UUID:%s | Content: %s",
					timestamp.Format(time.RFC3339), event.Pid, event.Pname, event.Uuid, preview(content, 120))
			} else {
				log.Printf("[STREAM]   %s | PID:%d (%s) | Chunk Len:%d | UUID:%s",
					timestamp.Format(time.RFC3339), event.Pid, event.Pname, len(content), event.Uuid)
			}
		}
	}
}

func (a *Auditor) auditLLMRequest(meta *pb.Event, req LLMRequest) {
	timestamp := time.Unix(0, meta.Timestamp) // 协议中 Timestamp 是 int64 纳秒

	for _, msg := range req.Messages {
		if msg.Role == "user" {
			if containsSensitiveContent(msg.Content) {
				log.Printf("[CRITICAL] %s | PID:%d (%s) | LEAK DETECTED | Model: %s | Content: %s",
					timestamp.Format(time.RFC3339), meta.Pid, meta.Pname, req.Model, preview(msg.Content, 120))
			} else {
				log.Printf("[AUDIT]    %s | PID:%d (%s) | LLM Access    | Model: %s | Prompt Len: %d",
					timestamp.Format(time.RFC3339), meta.Pid, meta.Pname, req.Model, len(msg.Content))
			}
		}
	}
}

func isLikelyLLMRequest(payload string) bool {
	lower := strings.ToLower(payload)
	if !strings.Contains(lower, "post ") {
		return false
	}

	return strings.Contains(lower, `"messages"`) ||
		strings.Contains(lower, `"prompt"`) ||
		strings.Contains(lower, "/chat/completions") ||
		strings.Contains(lower, "/responses")
}

func isLikelySSEResponse(payload string) bool {
	lower := strings.ToLower(payload)
	return strings.Contains(lower, "text/event-stream") || strings.Contains(lower, "data:")
}

func extractJSONBody(payload string) (string, bool) {
	if i := strings.Index(payload, "\r\n\r\n"); i >= 0 && i+4 < len(payload) {
		body := strings.TrimSpace(payload[i+4:])
		if strings.HasPrefix(body, "{") {
			return body, true
		}
	}

	if i := strings.Index(payload, "{"); i >= 0 {
		body := strings.TrimSpace(payload[i:])
		if strings.HasPrefix(body, "{") {
			return body, true
		}
	}

	return "", false
}

func extractSSEContent(data string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return ""
	}

	choices, ok := obj["choices"].([]any)
	if !ok {
		return ""
	}
	var out strings.Builder
	for _, choice := range choices {
		cmap, ok := choice.(map[string]any)
		if !ok {
			continue
		}

		delta, ok := cmap["delta"].(map[string]any)
		if !ok {
			continue
		}
		content, ok := delta["content"].(string)
		if !ok || content == "" {
			continue
		}
		out.WriteString(content)
	}
	return out.String()
}

func (a *Auditor) consumeSSEChunk(streamID, chunk string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	state := a.sseStreams[streamID]
	if state == nil {
		state = &sseParserState{}
		a.sseStreams[streamID] = state
	}
	state.lastSeen = now

	events := state.feed(chunk)
	a.cleanupStaleStreamsLocked(now)
	return events
}

func (a *Auditor) closeSSEStream(streamID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sseStreams, streamID)
}

func (a *Auditor) cleanupStaleStreamsLocked(now time.Time) {
	const maxIdle = 3 * time.Minute
	for id, s := range a.sseStreams {
		if now.Sub(s.lastSeen) > maxIdle {
			delete(a.sseStreams, id)
		}
	}
}

func (s *sseParserState) feed(chunk string) []string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(chunk, "\r\n", "\n"), "\r", "\n")
	input := s.pendingLine + normalized
	lines := strings.Split(input, "\n")
	if !strings.HasSuffix(input, "\n") {
		s.pendingLine = lines[len(lines)-1]
		lines = lines[:len(lines)-1]
	} else {
		s.pendingLine = ""
		// strings.Split("a\n", "\n") 会额外生成一个末尾空元素，这不代表 SSE 的空行分隔符。
		if len(lines) > 0 {
			lines = lines[:len(lines)-1]
		}
	}

	var out []string
	flush := func() {
		if len(s.currentData) == 0 {
			return
		}
		out = append(out, strings.Join(s.currentData, "\n"))
		s.currentData = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			s.currentData = append(s.currentData, data)
			if data == "[DONE]" {
				flush()
			}
			continue
		}
		if trimmed == "" {
			flush()
		}
	}

	return out
}

func containsSensitiveContent(text string) bool {
	lower := strings.ToLower(text)
	keywords := []string{
		"password", "passwd", "secret", "api_key", "apikey", "token", "sk-",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func preview(text string, maxLen int) string {
	if maxLen <= 0 || len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "...(truncated)"
}
