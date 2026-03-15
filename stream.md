HTTP/2 分片、流式传输
HTTP/2 包重组逻辑分析

核心架构

数据流向:
TLS解密数据 → EventProcessor → eventWorker → IParser(HTTP2Request/HTTP2Response) → Display()

关键文件

┌───────────────────┬────────────────────────┐
│       文件        │          作用          │
├───────────────────┼────────────────────────┤
│ http2_request.go  │ HTTP/2 请求帧解析      │
├───────────────────┼────────────────────────┤
│ http2_response.go │ HTTP/2 响应帧解析      │
├───────────────────┼────────────────────────┤
│ iworker.go        │ 数据缓冲与生命周期管理 │
├───────────────────┼────────────────────────┤
│ processor.go      │ 事件分发器             │
└───────────────────┴────────────────────────┘

HTTP/2 帧解析核心逻辑

http2_response.go:131-188 是核心解析代码：

// 使用 golang.org/x/net/http2 解析帧
for {
f, err := h2r.framer.ReadFrame()
switch f := f.(type) {
case *http2.HeadersFrame:
// 解析 HEADERS 帧，提取 content-encoding
fields, _ := h2r.hdec.DecodeFull(f.HeaderBlockFragment())
case *http2.DataFrame:
// 解析 DATA 帧，获取 body 数据
payload := f.Data()
// 支持 gzip 解压
}
}

二次开发指南：解包 HTTP/2 分片 + LLM 流式传输

1. 理解流式数据特点

LLM 流式响应（如 OpenAI API）使用 Server-Sent Events (SSE) 格式：
data: {"id":"chatcmpl-xxx","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-xxx","choices":[{"delta":{"content":" World"}}]}

data: [DONE]

2. 修改 HTTP2Response 支持流式解析

在 http2_response.go 中，DATA 帧的处理需要改为增量解析：

// 新增结构体保存流式状态
type HTTP2Response struct {
// ... 现有字段 ...
sseParser map[uint32]*SSEParser  // 按 StreamID 管理 SSE 解析器
}

// SSE 解析器
type SSEParser struct {
buffer    *bytes.Buffer
events    []SSEEvent
}

type SSEEvent struct {
Data  string
JSON  map[string]interface{}  // 解析后的 JSON
}

3. 处理 DATA 帧的增量解析

case *http2.DataFrame:
streamID := f.StreamID
payload := f.Data()

      // 初始化 SSE 解析器
      if h2r.sseParser[streamID] == nil {
          h2r.sseParser[streamID] = &SSEParser{
              buffer: bytes.NewBuffer(nil),
          }
      }

      // 增量写入并解析
      h2r.sseParser[streamID].buffer.Write(payload)
      h2r.parseSSEStream(streamID)

4. SSE 流式解析实现

func (h2r *HTTP2Response) parseSSEStream(streamID uint32) {
parser := h2r.sseParser[streamID]

      for {
          line, err := parser.buffer.ReadString('\n')
          if err != nil {
              // 数据不完整，等待更多数据
              return
          }

          line = strings.TrimSpace(line)
          if strings.HasPrefix(line, "data: ") {
              data := strings.TrimPrefix(line, "data: ")
              if data == "[DONE]" {
                  continue
              }

              // 解析 JSON
              var jsonData map[string]interface{}
              if err := json.Unmarshal([]byte(data), &jsonData); err == nil {
                  // 提取 content 字段
                  if choices, ok := jsonData["choices"].([]interface{}); ok {
                      for _, choice := range choices {
                          if delta, ok := choice.(map[string]interface{})["delta"].(map[string]interface{}); ok {
                              if content, ok := delta["content"].(string); ok {
                                  // 输出流式内容
                                  fmt.Printf("Stream %d: %s\n", streamID, content)
                              }
                          }
                      }
                  }
              }
          }
      }
}

5. 关键注意事项

┌─────────────┬───────────────────────────────────────────┐
│    问题     │                 解决方案                  │
├─────────────┼───────────────────────────────────────────┤
│ 帧分片      │ DATA 帧可能被拆分，需要缓冲区累积         │
├─────────────┼───────────────────────────────────────────┤
│ 多 StreamID │ HTTP/2 支持多路复用，按 StreamID 分别处理 │
├─────────────┼───────────────────────────────────────────┤
│ gzip 压缩   │ 流式 gzip 需要使用 gzip.Reader 增量读取   │
├─────────────┼───────────────────────────────────────────┤
│ HPACK 状态  │ 同一连接共享动态表，需要保持 hdec 状态    │
└─────────────┴───────────────────────────────────────────┘

6. 完整示例：提取 LLM 流式 JSON

// 在 Display() 方法中添加流式处理
func (h2r *HTTP2Response) Display() []byte {
// ... 现有代码 ...

      // 处理流式数据
      for streamID, parser := range h2r.sseParser {
          if parser.buffer.Len() > 0 {
              frameBuf.WriteString(fmt.Sprintf("\n=== Stream %d SSE Events ===\n", streamID))
              // 解析并输出所有完整事件
              h2r.parseSSEStream(streamID)
          }
      }

      return frameBuf.Bytes()
}

推荐开发路径

1. 复制 http2_response.go 创建 http2_response_stream.go
2. 添加 SSE 解析逻辑 处理 data: 格式
3. 实现 JSON 提取 使用 encoding/json 解析
4. 测试 使用 OpenAI API 或其他 LLM 服务验证