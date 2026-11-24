package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func fakeTool(name, desc string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc,
		Schema: obj(map[string]any{"q": str("query")}),
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		},
	})
}

func TestBM25Index(t *testing.T) {
	idx := newBM25Index(
		[]string{"authz_matrix", "nuclei_scan", "file_upload"},
		[]string{"越权 未授权 IDOR 双身份 接口", "nuclei 模板 扫描 漏洞", "上传 文件 解析"},
	)
	got := idx.search("越权 接口", 2)
	if len(got) == 0 || got[0] != "authz_matrix" {
		t.Fatalf("search = %v", got)
	}
	got = idx.search("nuclei 模板", 1)
	if len(got) != 1 || got[0] != "nuclei_scan" {
		t.Fatalf("search = %v", got)
	}
	if got := idx.search("", 3); len(got) != 0 {
		t.Fatalf("empty query = %v", got)
	}
}

func TestApplyToolVisibility(t *testing.T) {
	t.Setenv("POJUN_TOOL_VISIBILITY_LIMIT", "10")
	var tools []actool.CoreTool
	tools = append(tools, fakeTool("Bash", "run commands"), fakeTool("record_fact", "write fact"))
	for i := 0; i < 20; i++ {
		tools = append(tools, fakeTool(fmt.Sprintf("domain_tool_%d", i), "domain probe "+fmt.Sprint(i)))
	}
	tools = append(tools, fakeTool("authz_matrix", "越权 未授权 双身份 接口"))
	def := DeferredInfo{}
	ctx := WithToolQuery(context.Background(), "越权 接口 双身份")
	out, def := applyToolVisibility(ctx, tools, def)
	if len(def.Deferred) == 0 {
		t.Fatal("expected deferred tools")
	}
	visible := VisibleToolCount(out, def.Deferred)
	if visible > 11 { // limit + search_tools
		t.Fatalf("visible=%d, want <=11", visible)
	}
	if !containsTool(out, "Bash") || !containsTool(out, "record_fact") {
		t.Fatal("essential tools must stay visible")
	}
	if !containsTool(out, "search_tools") {
		t.Fatal("search_tools should be added")
	}
	if !containsTool(out, "authz_matrix") {
		t.Fatalf("BM25-selected authz_matrix should stay visible: %v", def.Deferred)
	}
	for _, n := range def.Deferred {
		if strings.HasPrefix(n, "domain_tool_") == false && n != "authz_matrix" {
			t.Fatalf("unexpected deferred name %q", n)
		}
	}
}

func TestApplyToolVisibilityOff(t *testing.T) {
	t.Setenv("POJUN_TOOL_VISIBILITY_LIMIT", "0")
	tools := []actool.CoreTool{fakeTool("Bash", "run"), fakeTool("x", "x")}
	out, def := applyToolVisibility(context.Background(), tools, DeferredInfo{})
	if len(out) != 2 || len(def.Deferred) != 0 {
		t.Fatalf("limit off should be a no-op: out=%d deferred=%v", len(out), def.Deferred)
	}
}

func TestToolSearchTool(t *testing.T) {
	tools := []actool.CoreTool{
		fakeTool("Bash", "run commands"),
		fakeTool("authz_matrix", "越权 未授权 双身份 接口"),
	}
	idxTool := buildToolSearchTool(tools, map[string]bool{"authz_matrix": true})
	res, err := idxTool.Call(context.Background(), json.RawMessage(`{"query":"越权 接口","limit":5}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	text := res.Flatten()
	if !strings.Contains(text, "authz_matrix") || !strings.Contains(text, `"deferred":true`) {
		t.Fatalf("search result = %s", text)
	}
}

func containsTool(tools []actool.CoreTool, name string) bool {
	for _, t := range tools {
		if t.Name() == name {
			return true
		}
	}
	return false
}
