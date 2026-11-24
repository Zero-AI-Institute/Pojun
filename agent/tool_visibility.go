package agent

// P2-2 工具可见性上限 + BM25 选择。
//
// 工具 schema 是 system prompt 里最稳定也最占位的部分。默认保留 30 个可见工具
// （核心/写回/常用执行面 + 按当前任务意图 BM25 选出的领域工具），其余进入
// deferred 机制：schema 不进 prompt，只列名字；模型通过 SDK 的 SearchExtraTools /
// ExecuteExtraTool 或本包的 search_tools（BM25）发现并调用。
//
// 约束：
//   - 写回/核心执行工具永远可见（见 essentialToolNames），避免"工具被藏了导致
//     任务不会写回"这类产出下降；
//   - POJUN_TOOL_VISIBILITY_LIMIT=0 关闭上限，行为回到全量可见；
//   - 只影响模型看到的 schema，不改变工具注册/权限/执行。

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
)

const defaultToolVisibilityLimit = 0 // 默认关闭；设置 POJUN_TOOL_VISIBILITY_LIMIT=30 才启用

// ToolVisibilityLimit is a package hook so the server can later wire a setting.
// nil/unset = env POJUN_TOOL_VISIBILITY_LIMIT (0=off, default off).
var ToolVisibilityLimit func() int

func toolVisibilityLimit() int {
	if ToolVisibilityLimit != nil {
		return ToolVisibilityLimit()
	}
	if v := strings.TrimSpace(os.Getenv("POJUN_TOOL_VISIBILITY_LIMIT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 0 {
				return 0
			}
			return n
		}
	}
	return defaultToolVisibilityLimit
}

// essentialToolNames are always visible. They are the "must not lose output"
// backbone: shell/file access, graph write-back, native HTTP, goal/coverage
// controls, and the deferred-discovery tools themselves.
var essentialToolNames = map[string]bool{
	"Bash": true, "Read": true, "Write": true, "Edit": true, "MultiEdit": true,
	"LS": true, "Glob": true, "Grep": true, "WebFetch": true, "WebSearch": true,
	"TodoWrite": true, "Skill": true,
	"record_fact": true, "report_finding": true, "insert_assets": true, "save_evidence": true,
	"node_detail": true, "list_findings": true,
	"http_request": true, "session_login": true, "http_probe": true, "js_audit": true,
	"add_intent": true, "prove_goal": true, "goal_met": true, "graph_overview": true,
	"list_facts": true, "audit_finding": true, "add_task_scope": true,
	"set_goals": true, "add_hint": true,
	"get_finding_traffic": true, "get_task_node_detail": true,
	"traffic_search": true, "traffic_get": true, "bind_finding_traffic": true,
}

type toolQueryCtxKey struct{}

// WithToolQuery carries the task/intent text used to rank tools for visibility.
func WithToolQuery(ctx context.Context, query string) context.Context {
	if strings.TrimSpace(query) == "" {
		return ctx
	}
	return context.WithValue(ctx, toolQueryCtxKey{}, query)
}

func toolQueryFromContext(ctx context.Context) string {
	s, _ := ctx.Value(toolQueryCtxKey{}).(string)
	return s
}

// applyToolVisibility caps the visible tool set and wires deferred names. It
// returns the (possibly extended) tool slice and DeferredInfo.
func applyToolVisibility(ctx context.Context, tools []actool.CoreTool, def DeferredInfo) ([]actool.CoreTool, DeferredInfo) {
	limit := toolVisibilityLimit()
	if limit <= 0 || len(tools) == 0 {
		return tools, def
	}
	deferredSet := make(map[string]bool, len(def.Deferred))
	for _, n := range def.Deferred {
		deferredSet[n] = true
	}
	visible := 0
	presentEssential := 0
	candidates := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if deferredSet[t.Name()] {
			continue
		}
		visible++
		if essentialToolNames[t.Name()] {
			presentEssential++
			continue
		}
		candidates = append(candidates, t)
	}
	if visible <= limit || len(candidates) == 0 {
		return tools, def
	}
	need := limit - presentEssential
	if need < 0 {
		need = 0
	}
	if need > len(candidates) {
		need = len(candidates)
	}

	selected := map[string]bool{}
	query := toolQueryFromContext(ctx)
	if query != "" && need > 0 {
		idx := buildToolBM25(tools)
		for _, n := range idx.search(query, need) {
			selected[n] = true
		}
	}
	// BM25 命中不足（query 为空/术语不匹配）时按原始顺序补齐，保证上限内
	// 始终有 need 个领域工具，而不是把整类工具全藏掉。
	if len(selected) < need {
		for _, t := range candidates {
			if len(selected) >= need {
				break
			}
			selected[t.Name()] = true
		}
	}

	seenGlobal := make(map[string]bool, len(def.GlobalNames))
	for _, n := range def.GlobalNames {
		seenGlobal[n] = true
	}
	for _, t := range candidates {
		name := t.Name()
		if selected[name] {
			continue
		}
		if deferredSet[name] {
			continue
		}
		deferredSet[name] = true
		def.Deferred = append(def.Deferred, name)
		if !seenGlobal[name] {
			def.GlobalNames = append(def.GlobalNames, name)
			seenGlobal[name] = true
		}
		if def.Unlock != nil {
			def.Unlock.Add(name)
		}
	}
	if len(def.Deferred) == 0 {
		return tools, def
	}
	// BM25 discovery tool: supplemental to the SDK's keyword SearchExtraTools.
	tools = append(tools, buildToolSearchTool(tools, deferredSet))
	return tools, def
}

func buildToolBM25(tools []actool.CoreTool) *bm25Index {
	names := make([]string, 0, len(tools))
	texts := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name())
		schema := ""
		if s := t.InputSchema(); len(s) > 0 {
			if b, err := json.Marshal(s); err == nil {
				schema = string(b)
			}
		}
		texts = append(texts, t.Name()+" "+t.Description()+" "+t.Prompt()+" "+schema)
	}
	return newBM25Index(names, texts)
}

// buildToolSearchTool exposes BM25 ranking to the model when some tools are
// deferred. It returns name/description/schema so the model can then invoke the
// tool via the SDK's ExecuteExtraTool.
func buildToolSearchTool(tools []actool.CoreTool, deferred map[string]bool) actool.CoreTool {
	byName := make(map[string]actool.CoreTool, len(tools))
	for _, t := range tools {
		byName[t.Name()] = t
	}
	idx := buildToolBM25(tools)
	return actool.Build(actool.Spec{
		Name: "search_tools",
		Description: "BM25 搜索工具（包括当前被延迟、schema 未加载的工具）。" +
			"返回 name/description/input_schema 与是否 deferred；延迟工具用 ExecuteExtraTool 调用。",
		Schema: obj(map[string]any{
			"query": str("自然语言或关键词，例如「越权 未授权 接口」「nuclei 模板扫描」"),
			"limit": intp("返回条数，默认 8，最大 20"),
		}, "query"),
		ReadOnly: func(json.RawMessage) bool { return true },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query 必填"), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 8
			}
			if limit > 20 {
				limit = 20
			}
			names := idx.search(a.Query, limit)
			matches := make([]map[string]any, 0, len(names))
			for _, n := range names {
				t := byName[n]
				if t == nil {
					continue
				}
				m := map[string]any{
					"name": n, "description": t.Description(),
					"deferred": deferred[n], "invoke_with": "ExecuteExtraTool",
				}
				if s := t.InputSchema(); len(s) > 0 {
					m["input_schema"] = s
				}
				matches = append(matches, m)
			}
			return jsonResult(map[string]any{"query": a.Query, "matches": matches, "count": len(matches)})
		},
	})
}

// VisibleToolCount is a small helper for tests/diagnostics.
func VisibleToolCount(tools []actool.CoreTool, deferred []string) int {
	set := make(map[string]bool, len(deferred))
	for _, n := range deferred {
		set[n] = true
	}
	n := 0
	for _, t := range tools {
		if !set[t.Name()] {
			n++
		}
	}
	return n
}

// intentToolQuery makes a short BM25 query from the intent's own text. It never
// includes tool output, so a hostile target cannot influence tool ranking.
func intentToolQuery(intent *db.Node) string {
	if intent == nil || len(intent.Payload) == 0 {
		return ""
	}
	var p struct {
		Summary         string `json:"summary"`
		Title           string `json:"title"`
		Hypothesis      string `json:"hypothesis"`
		SuccessCriteria string `json:"success_criteria"`
	}
	_ = json.Unmarshal(intent.Payload, &p)
	parts := []string{p.Summary, p.Title, p.Hypothesis, p.SuccessCriteria}
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return strings.Join(out, " ")
}
