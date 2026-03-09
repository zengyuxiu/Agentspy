package client

import (
	"context"
	"errors"
	"log"
	"time"

	"xiu.zyx/agentspy/internal/auditor"

	pb "github.com/gojue/ecapture/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

type Config struct {
	ServerURL     string
	Origin        string
	RetryInterval time.Duration
}

type AgentClient struct {
	cfg     Config
	auditor *auditor.Auditor
}

func NewAgentClient(cfg Config) *AgentClient {
	return NewAgentClientWithAuditor(cfg, auditor.NewAuditor())
}

func NewAgentClientWithAuditor(cfg Config, aud *auditor.Auditor) *AgentClient {
	if cfg.Origin == "" {
		cfg.Origin = "http://localhost/"
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 5 * time.Second
	}
	if aud == nil {
		aud = auditor.NewAuditor()
	}

	return &AgentClient{
		cfg:     cfg,
		auditor: aud,
	}
}

// Start 启动并保持连接，直到 context 取消。
func (c *AgentClient) Start(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		log.Printf("Connecting to eCapture at %s...", c.cfg.ServerURL)
		ws, err := websocket.Dial(c.cfg.ServerURL, "", c.cfg.Origin)
		if err != nil {
			log.Printf("Connection failed: %v. Retrying in %s...", err, c.cfg.RetryInterval)
			select {
			case <-time.After(c.cfg.RetryInterval):
				continue
			case <-ctx.Done():
				return nil
			}
		}

		err = c.handleConnection(ctx, ws)
		_ = ws.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("Connection closed: %v", err)
		}

		select {
		case <-time.After(c.cfg.RetryInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *AgentClient) handleConnection(ctx context.Context, ws *websocket.Conn) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.receiveLoop(ws)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return context.Canceled
	}
}

func (c *AgentClient) receiveLoop(ws *websocket.Conn) error {
	log.Println("Connected. Waiting for events...")

	for {
		var msgData []byte
		err := websocket.Message.Receive(ws, &msgData)
		if err != nil {
			return err
		}

		var logEntry pb.LogEntry
		if err := proto.Unmarshal(msgData, &logEntry); err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		switch logEntry.LogType {
		case pb.LogType_LOG_TYPE_HEARTBEAT:
			continue
		case pb.LogType_LOG_TYPE_PROCESS_LOG:
			continue
		case pb.LogType_LOG_TYPE_EVENT:
			if evt := logEntry.GetEventPayload(); evt != nil {
				c.auditor.HandleEvent(evt)
			}
		default:
			log.Printf("Unknown LogType: %v", logEntry.LogType)
		}
	}
}
