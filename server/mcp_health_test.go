package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestRedactMCPError(t *testing.T) {
	m := &db.MCPServer{Env: json.RawMessage(`{"X-API-Key":"supersecretvalue","EMPTY":""}`)}
	raw := errors.New("dial https://alice:p%40ss@mcp.example.com/sse?token=abc123 failed; key=supersecretvalue")
	got := redactMCPError(m, raw)

	for _, leak := range []string{"alice", "p%40ss", "token=abc123", "supersecretvalue"} {
		if strings.Contains(got, leak) {
			t.Errorf("redacted error leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "mcp.example.com") {
		t.Errorf("host should remain for diagnosis: %s", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("error must be single-line: %q", got)
	}
	if len([]rune(got)) > 501 {
		t.Errorf("error too long: %d runes", len([]rune(got)))
	}
}

func TestRedactMCPErrorNilSafe(t *testing.T) {
	if got := redactMCPError(nil, nil); got != "" {
		t.Errorf("nil error should produce empty message: %q", got)
	}
	// 没有 env 也不能 panic。
	if got := redactMCPError(&db.MCPServer{}, errors.New("boom")); got != "boom" {
		t.Errorf("got %q", got)
	}
}

func TestMCPHealthTimeoutBound(t *testing.T) {
	// 启动自检不能无限等一个挂死的 stdio MCP；30s 是上限。
	if mcpHealthCheckTimeout <= 0 || mcpHealthCheckTimeout > 60*time.Second {
		t.Fatalf("mcpHealthCheckTimeout = %v", mcpHealthCheckTimeout)
	}
}
