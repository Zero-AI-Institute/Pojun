package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/pricing"
)

// estimateUSDCost 按模型名估算一次用量成本；定价表在 pricing 包（server 与
// 离线评测 harness 共用同一份，避免两边算出的成本对不上）。
func estimateUSDCost(model string, inTok, outTok int) (usd float64, known bool) {
	return pricing.Estimate(model, int64(inTok), int64(outTok))
}

// profileCost 是按 profile 聚合的成本视图。
type profileCost struct {
	ProfileName  string  `json:"profile_name"`
	Calls        int     `json:"calls"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// pgUsageCost 返回成本估算。?task=<id> 时返回该任务（按模型分别定价）；
// 否则返回全站按 profile 聚合 + 总计。所有金额都是"内置参考价估算"，响应里
// 原样带 unpriced_models 让前端提示哪些模型无法定价（而不是把它们算成免费）。
func (s *Server) pgUsageCost(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"total_cost_usd": 0})
		return
	}
	if task := strings.TrimSpace(r.URL.Query().Get("task")); task != "" {
		rows, err := pg.UsageModelsByTask(task)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		var total db.TaskUsage
		total.TaskID = task
		var cost float64
		unpriced := map[string]bool{}
		for _, row := range rows {
			c, known := estimateUSDCost(row.Model, row.InputTokens, row.OutputTokens)
			cost += c
			if !known {
				unpriced[row.Model] = true
			}
			total.Calls += row.Calls
			total.InputTokens += row.InputTokens
			total.OutputTokens += row.OutputTokens
		}
		writeJSON(w, 200, map[string]any{
			"task":            total,
			"cost_usd":        round4(cost),
			"unpriced_models": keysOf(unpriced),
			"pricing_note":    "按内置参考价估算（USD/百万 token），仅用于相对对比，不承诺账单精度；不含已归档任务。",
		})
		return
	}

	rows, err := pg.UsageByModel()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	byProfile := map[string]*profileCost{}
	var totalIn, totalOut int
	var totalCost float64
	unpriced := map[string]bool{}
	for _, row := range rows {
		c, known := estimateUSDCost(row.Model, row.InputTokens, row.OutputTokens)
		if !known {
			unpriced[row.Model] = true
		}
		p := byProfile[row.ProfileName]
		if p == nil {
			p = &profileCost{ProfileName: row.ProfileName}
			byProfile[row.ProfileName] = p
		}
		p.Calls += row.Calls
		p.InputTokens += row.InputTokens
		p.OutputTokens += row.OutputTokens
		p.CostUSD += c
		totalIn += row.InputTokens
		totalOut += row.OutputTokens
		totalCost += c
	}
	out := make([]profileCost, 0, len(byProfile))
	for _, p := range byProfile {
		p.CostUSD = round4(p.CostUSD)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	writeJSON(w, 200, map[string]any{
		"total": map[string]any{
			"input_tokens":  totalIn,
			"output_tokens": totalOut,
			"cost_usd":      round4(totalCost),
		},
		"by_profile":      out,
		"unpriced_models": keysOf(unpriced),
		"pricing_note":    "按内置参考价估算（USD/百万 token），仅用于相对对比，不承诺账单精度；不含已归档任务。",
	})
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
