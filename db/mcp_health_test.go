package db

import (
	"encoding/json"
	"testing"
	"time"
)

// MCP 健康字段是 v0.4.107 新增的 mcp_servers 列：last_ok NULL=未检查，
// 失败保留旧 tool_count，成功才覆盖。
func TestMCPHealthRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()

	name := "t-health-" + time.Now().Format("150405.000000000")
	d.Exec(`DELETE FROM mcp_servers WHERE name=$1`, name)
	t.Cleanup(func() { d.Exec(`DELETE FROM mcp_servers WHERE name=$1`, name) })

	id, err := d.SaveMCP(&MCPServer{
		Name: name, Transport: "stdio", Command: "true",
		Args: json.RawMessage(`[]`), Env: json.RawMessage(`{}`), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	load := func() *MCPServer {
		all, err := d.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range all {
			if m.ID == id {
				return m
			}
		}
		t.Fatalf("mcp %d not found", id)
		return nil
	}

	// 从未检查：LastOK 必须是 nil（前端据此显示“未检查”，而不是“异常”）。
	if m := load(); m.LastOK != nil || m.LastCheckAt != nil {
		t.Fatalf("new mcp should be unchecked: ok=%v at=%v", m.LastOK, m.LastCheckAt)
	}

	// 失败：错误入库、延迟入库、旧 tool_count 不被清零。
	if err := d.SaveMCPHealth(id, false, 120*time.Millisecond, "连接超时", 0); err != nil {
		t.Fatal(err)
	}
	m := load()
	if m.LastOK == nil || *m.LastOK {
		t.Fatalf("last_ok = %v, want false", m.LastOK)
	}
	if m.LastError != "连接超时" || m.LastLatencyMS != 120 {
		t.Fatalf("health = %q/%d", m.LastError, m.LastLatencyMS)
	}
	if m.LastCheckAt == nil {
		t.Fatal("last_check_at should be set")
	}

	// 成功：清错误、写 tool_count。
	if err := d.SaveMCPHealth(id, true, 80*time.Millisecond, "ignored", 7); err != nil {
		t.Fatal(err)
	}
	m = load()
	if m.LastOK == nil || !*m.LastOK {
		t.Fatalf("last_ok = %v, want true", m.LastOK)
	}
	if m.LastError != "" || m.ToolCount != 7 || m.LastLatencyMS != 80 {
		t.Fatalf("health after success = %q/%d/%d", m.LastError, m.ToolCount, m.LastLatencyMS)
	}

	// 之后失败：错误置位，但上次成功的 tool_count 保留（UI 仍能显示“曾有 7 个工具”）。
	if err := d.SaveMCPHealth(id, false, 50*time.Millisecond, "network down", 0); err != nil {
		t.Fatal(err)
	}
	m = load()
	if m.LastOK == nil || *m.LastOK || m.ToolCount != 7 {
		t.Fatalf("failure should keep tool_count: ok=%v count=%d", m.LastOK, m.ToolCount)
	}
}
