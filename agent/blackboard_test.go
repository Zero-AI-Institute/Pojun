package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// bigBlackboard 构造一个"跑了几十轮之后"的态势：大量目标/hints/经验/失败方向/
// 事实。Index 必须在 3KB 内，且 hints 与失败方向不能被折叠掉。
func bigBlackboard() map[string]any {
	goals := make([]map[string]any, 0, 20)
	for i := 1; i <= 20; i++ {
		state := "open"
		if i%4 == 0 {
			state = "met"
		}
		g := map[string]any{"id": i, "state": state, "text": strings.Repeat("目标描述", 20)}
		if i == 1 {
			g["criteria"] = "拿到管理员权限；导出 100 条数据"
		}
		goals = append(goals, g)
	}
	hints := make([]map[string]any, 0, 12)
	for i := 1; i <= 12; i++ {
		hints = append(hints, map[string]any{"id": 500 + i, "state": "active", "text": strings.Repeat("战略提示", 20)})
	}
	lessons := make([]map[string]any, 0, 8)
	for i := 1; i <= 8; i++ {
		lessons = append(lessons, map[string]any{
			"intent_id": 700 + i, "dimension": "authz", "state": "exhausted",
			"reason": "连续3轮无写回", "lesson": strings.Repeat("这条打法已经失败", 12),
		})
	}
	done := make([]map[string]any, 0, 30)
	for i := 1; i <= 30; i++ {
		it := map[string]any{
			"id": 900 + i, "state": "done", "summary": strings.Repeat("已跑完的方向", 15),
			"yields": []any{float64(1), float64(2)},
		}
		if i%3 == 0 {
			it["state"] = "exhausted"
			it["stop_reason"] = "连续3轮无写回（产出率已归零）"
			delete(it, "yields")
		}
		done = append(done, it)
	}
	facts := make([]map[string]any, 0, 20)
	for i := 1; i <= 20; i++ {
		facts = append(facts, map[string]any{"id": 1000 + i, "summary": strings.Repeat("最新事实", 10), "confidence": "observed"})
	}
	findings := make([]map[string]any, 0, 10)
	for i := 1; i <= 10; i++ {
		findings = append(findings, map[string]any{"id": 2000 + i, "summary": strings.Repeat("漏洞", 10)})
	}
	return map[string]any{
		"task":                map[string]any{"description": "对目标做完整渗透", "goal": strings.Repeat("拿到高危漏洞并证明影响", 10)},
		"goals":               goals,
		"hints":               hints,
		"recent_lessons":      lessons,
		"recent_done_intents": done,
		"recent_facts":        facts,
		"finding_list":        findings,
		"frontier_open":       3,
		"done_intents_total":  120,
		"facts":               88,
		"findings_total":      4,
		"running_intents":     []map[string]any{{"id": 1, "summary": "在跑"}},
		"coverage": map[string]any{
			"denominator": 40, "tested": 18, "pct": 45, "host_count": 6,
			"matrix": map[string]any{
				"assets": 40, "tested": 18, "in_progress": 2, "untested_assets": 20, "findings": 4,
				"top_gaps": []map[string]any{
					{"dimension": "authz", "asset_type": "api", "untested": 7},
					{"dimension": "injection", "asset_type": "api", "untested": 5},
				},
			},
		},
		"tools": map[string]any{"available": []any{"sqlmap: SQL 注入", "nuclei: 模板扫描"}, "missing": []any{"x"}},
	}
}

func TestBlackboardIndexBudgetAndNeverFoldsHints(t *testing.T) {
	idx := renderBlackboardIndex(bigBlackboard())
	if len(idx) > blackboardIndexBudgetBytes {
		t.Fatalf("Index 超预算: %d > %d bytes\n%s", len(idx), blackboardIndexBudgetBytes, idx)
	}
	for _, want := range []string{"态势索引", "HINTS", "经验", "失败/零产", "#501", "#909", "验收"} {
		if !strings.Contains(idx, want) {
			t.Errorf("Index 缺少 %q:\n%s", want, idx)
		}
	}
}

func TestBlackboardSummaryKeepsHintsAndFailedDirections(t *testing.T) {
	data := bigBlackboard()
	sum := trimSummaryToBudget(blackboardSummaryData(data))
	if got := jsonBytes(sum); got > blackboardSummaryBudgetBytes {
		t.Fatalf("Summary 超预算: %d > %d", got, blackboardSummaryBudgetBytes)
	}
	// 窗口化：事实/漏洞被截到 8 条。
	if got := len(sliceMaps(sum["recent_facts"])); got != 8 {
		t.Errorf("recent_facts 窗口 = %d, want 8", got)
	}
	// 不折叠：hints 与 lessons 仍在。
	if got := len(sliceMaps(sum["hints"])); got != 12 {
		t.Errorf("hints 不应被折叠: got %d", got)
	}
	if got := len(sliceMaps(sum["recent_lessons"])); got != 8 {
		t.Errorf("recent_lessons 不应被折叠: got %d", got)
	}
	// 失败方向优先保留（#903 是第 3 条，零 yields 的 exhausted）。
	foundFailed := false
	for _, it := range sliceMaps(sum["recent_done_intents"]) {
		if intValue(it["id"]) == 903 {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Errorf("recent_done 窗口应优先保留失败方向 #903: %v", sum["recent_done_intents"])
	}
}

func TestBlackboardSummaryDropsRawToolCatalog(t *testing.T) {
	sum := blackboardSummaryData(bigBlackboard())
	tools := mapValue(sum["tools"])
	if tools == nil {
		t.Fatal("summary 应保留工具名（压缩形态）")
	}
	if _, ok := tools["available"]; !ok {
		t.Error("summary 应保留 available（只留命令名，不带用途）")
	}
	for _, x := range anySlice(tools["available"]) {
		if strings.Contains(textValue(x), "SQL 注入") {
			t.Errorf("summary 不应重复工具用途说明: %v", x)
		}
	}
}

func TestRenderGraphOverviewLayered(t *testing.T) {
	s := renderGraphOverview(bigBlackboard())
	for _, want := range []string{"本轮态势索引", "态势摘要", "HINTS", "失败/零产", `"view":"summary"`} {
		if !strings.Contains(s, want) {
			t.Errorf("分层态势缺少 %q", want)
		}
	}
	if len(s) > blackboardSummaryBudgetBytes+blackboardIndexBudgetBytes+800 {
		t.Errorf("分层态势总体过大: %d bytes", len(s))
	}
}

func TestParseBlackboardView(t *testing.T) {
	cases := map[string]BlackboardView{
		"": BlackboardSummary, "summary": BlackboardSummary, "index": BlackboardIndex,
		"brief": BlackboardIndex, "full": BlackboardFull, "raw": BlackboardFull,
	}
	for in, want := range cases {
		if got := parseBlackboardView(in); got != want {
			t.Errorf("parse(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFailedIntentsIncludesZeroYieldDone(t *testing.T) {
	data := map[string]any{"recent_done_intents": []map[string]any{
		{"id": 1, "state": "done", "yields": []any{float64(1)}},
		{"id": 2, "state": "done", "summary": "零写回"},
		{"id": 3, "state": "exhausted"},
	}}
	got := failedIntents(data, 10)
	if len(got) != 2 {
		t.Fatalf("失败方向 = %d, want 2", len(got))
	}
	if got[0]["id"] != 2 || got[1]["id"] != 3 {
		t.Errorf("失败方向 ids = %v", []any{got[0]["id"], got[1]["id"]})
	}
}

func TestBlackboardIndexEmptyData(t *testing.T) {
	if got := renderBlackboardIndex(nil); got != "" {
		t.Errorf("空态势应返回空串: %q", got)
	}
}

func TestBlackboardSummaryMarshalable(t *testing.T) {
	if _, err := json.Marshal(blackboardSummaryData(bigBlackboard())); err != nil {
		t.Fatalf("summary 必须可序列化: %v", err)
	}
}

// 意图摘要可能很长（线上平均 737 字/最长 2267 字）。Summary 必须把 open/running
// 也窗口化，否则 8 条长意图就能把 12KB 预算吃光，进而把 hints/经验正文压到 0。
func TestBlackboardSummaryBudgetWithLongIntents(t *testing.T) {
	data := bigBlackboard()
	long := strings.Repeat("这是一个很长的探索方向描述", 120)
	open := make([]map[string]any, 0, 8)
	running := make([]map[string]any, 0, 8)
	for i := 0; i < 8; i++ {
		open = append(open, map[string]any{"id": 3000 + i, "state": "open", "summary": long, "asset_ids": []any{1, 2, 3}})
		running = append(running, map[string]any{"id": 4000 + i, "state": "running", "summary": long, "asset_ids": []any{1}})
	}
	data["open_intents"] = open
	data["running_intents"] = running
	sum := trimSummaryToBudget(blackboardSummaryData(data))
	if got := jsonBytes(sum); got > blackboardSummaryBudgetBytes {
		t.Fatalf("长意图场景 Summary 超预算: %d > %d", got, blackboardSummaryBudgetBytes)
	}
	for _, m := range sliceMaps(sum["hints"]) {
		if textValue(m["text"]) == "" {
			t.Fatalf("长意图不应把 hints 正文压空: %v", m)
		}
	}
}
