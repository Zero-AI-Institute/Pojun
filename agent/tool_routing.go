package agent

// P2-1 工具路由学习（只读、提示层）：把本任务同维度终态意图的历史工具表现
// 注入 worker 的 system prompt，帮助它避开高错误率手段。数据来自
// activity + intent_reflections；没有足够样本时返回空串，提示词逐字不变。
//
// 这不是硬性禁用：未列出的工具仍可用，列出的工具也不是不能用——只是把
// 「这个维度里哪条路反复报错」提前告诉模型，减少重复踩坑。

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chu0119/pojun/db"
)

// toolRoutingExclude 是写回/控制类工具：它们的失败是平台/参数问题，不是
// 「这个维度的探测手段」；统计里排除，避免误导 worker 换掉写回工具。
var toolRoutingExclude = map[string]bool{
	"record_fact": true, "report_finding": true, "insert_assets": true,
	"save_evidence": true, "add_intent": true, "set_goals": true,
	"prove_goal": true, "goal_met": true, "add_hint": true,
	"add_task_scope": true, "retire_intent": true, "steer_work": true,
	"kill_work": true, "job_start": true, "job_stop": true,
	"save_script": true, "Skill": true, "TodoWrite": true,
}

// toolRoutingBlock renders the dimension-scoped tool history. Empty when there
// are fewer than two tools or fewer than 8 total uses (not enough signal).
func toolRoutingBlock(ts *db.ExplorationStore, intent *db.Node, limit int) string {
	if ts == nil || intent == nil {
		return ""
	}
	var p struct {
		Dimension string `json:"dimension"`
		Summary   string `json:"summary"`
		Title     string `json:"title"`
	}
	_ = json.Unmarshal(intent.Payload, &p)
	summary := p.Summary
	if summary == "" {
		summary = p.Title
	}
	dim := IntentDimension(p.Dimension, summary)
	if dim == "" || dim == dimOther {
		return ""
	}
	if limit <= 0 {
		limit = 5
	}
	stats, err := ts.ToolOutcomeStats(dim, limit)
	if err != nil {
		return ""
	}
	riskyRaw, _ := ts.HighErrorTools(dim, 5, 0.6, 3)
	best := make([]db.ToolOutcomeStat, 0, len(stats))
	risky := make([]db.ToolOutcomeStat, 0, len(riskyRaw))
	total := 0
	seen := map[string]bool{}
	accept := func(st db.ToolOutcomeStat, high bool) {
		if toolRoutingExclude[st.Tool] || st.Uses <= 0 || seen[st.Tool] {
			return
		}
		rate := float64(st.Errors) / float64(st.Uses)
		if high && rate < 0.6 {
			return
		}
		if !high && rate >= 0.6 {
			return
		}
		seen[st.Tool] = true
		total += st.Uses
		if high {
			risky = append(risky, st)
		} else {
			best = append(best, st)
		}
	}
	for _, st := range stats {
		accept(st, false)
	}
	for _, st := range riskyRaw {
		accept(st, true)
	}
	if len(best)+len(risky) < 2 || total < 8 {
		return ""
	}
	return renderToolRoutingStats(dim, best, risky)
}

// renderToolRoutingStats is pure so it can be tested without a DB.
func renderToolRoutingStats(dim string, best, risky []db.ToolOutcomeStat) string {
	if len(best) == 0 && len(risky) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【本维度工具表现（历史，仅参考；不是限制）】")
	b.WriteString("\n维度：" + DimensionLabel(dim) + "。")
	writeStats := func(items []db.ToolOutcomeStat) {
		for _, st := range items {
			rate := 0.0
			if st.Uses > 0 {
				rate = float64(st.Errors) / float64(st.Uses) * 100
				if rate > 100 {
					rate = 100 // 一个 use 可能对应多条 error result；展示封顶
				}
			}
			b.WriteString(fmt.Sprintf("\n- %s：%d 次 / 错误 %d（%.0f%%）", st.Tool, st.Uses, st.Errors, rate))
		}
	}
	if len(best) > 0 {
		b.WriteString("\n按历史错误率从低到高：")
		writeStats(best)
	}
	if len(risky) > 0 {
		b.WriteString("\n【本维度历史高错误率（优先换参数/换入口/换工具）】")
		writeStats(risky)
	}
	b.WriteString("\n高错误率的工具先换参数/换入口/换工具；不要把同一失败打法重复 3 次以上。未列出的工具不代表不能用。")
	return b.String()
}
