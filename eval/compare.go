package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Comparison 是一次 A/B 运行对比（v0.4.108）。用途是回归：同一 scenario
// 在改代码/换模型/换预算后重跑，看 pass 是否退步、成本是否失控。
type Comparison struct {
	ScenarioID   string `json:"scenario_id"`
	ScenarioName string `json:"scenario_name"`
	TaskA        int64  `json:"task_a"`
	TaskB        int64  `json:"task_b"`

	PassBefore bool `json:"pass_before"`
	PassAfter  bool `json:"pass_after"`
	Regressed  bool `json:"regressed"`
	Improved   bool `json:"improved"`

	RequiredFoundDelta int     `json:"required_found_delta"`
	UnexpectedDelta    int     `json:"unexpected_delta"`
	EvidenceDelta      float64 `json:"evidence_completeness_delta"`
	StageDelta         int     `json:"stages_seen_delta"`
	TokensDelta        int64   `json:"tokens_delta"`
	CostDeltaUSD       float64 `json:"cost_delta_usd"`
	DurationDeltaMin   float64 `json:"duration_delta_minutes"`

	// NewlyMissing / NewlyFound 按 vulnclass+asset 对齐，便于直接看出退步点。
	NewlyMissing []string `json:"newly_missing,omitempty"`
	NewlyFound   []string `json:"newly_found,omitempty"`
}

// CompareRuns 要求两次运行属于同一 scenario；不同 scenario 直接拒绝。
func CompareRuns(a, b *RunResult) (*Comparison, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("两个运行结果都不能为空")
	}
	if a.ScenarioID != b.ScenarioID {
		return nil, fmt.Errorf("scenario 不一致: %s vs %s", a.ScenarioID, b.ScenarioID)
	}
	c := &Comparison{
		ScenarioID: a.ScenarioID, ScenarioName: a.ScenarioName,
		TaskA: a.TaskID, TaskB: b.TaskID,
		PassBefore: a.Pass, PassAfter: b.Pass,
		Regressed: a.Pass && !b.Pass, Improved: !a.Pass && b.Pass,
		RequiredFoundDelta: b.RequiredFound - a.RequiredFound,
		UnexpectedDelta:    b.UnexpectedN - a.UnexpectedN,
		EvidenceDelta:      b.EvidenceCompleteness - a.EvidenceCompleteness,
		StageDelta:         b.StagesSeen - a.StagesSeen,
		TokensDelta:        (b.TokensInput + b.TokensOutput) - (a.TokensInput + a.TokensOutput),
		CostDeltaUSD:       b.CostUSD - a.CostUSD,
		DurationDeltaMin:   b.DurationMinutes - a.DurationMinutes,
	}
	aMap := expectedMap(a)
	bMap := expectedMap(b)
	for k := range aMap {
		if !bMap[k] {
			c.NewlyMissing = append(c.NewlyMissing, k)
		}
	}
	for k := range bMap {
		if !aMap[k] {
			c.NewlyFound = append(c.NewlyFound, k)
		}
	}
	sort.Strings(c.NewlyMissing)
	sort.Strings(c.NewlyFound)
	return c, nil
}

func expectedMap(r *RunResult) map[string]bool {
	out := map[string]bool{}
	for _, e := range r.Expected {
		if !e.Matched {
			continue
		}
		key := e.VulnClass
		if e.Asset != "" {
			key += "@" + e.Asset
		}
		out[key] = true
	}
	return out
}

// WriteJSON 原子写文件（先写 .tmp 再 rename），避免评测中断留下半个结果。
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadRunResult 读取一次评分结果。
func ReadRunResult(path string) (*RunResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r RunResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.ScenarioID == "" {
		return nil, fmt.Errorf("%s: 不是有效的 RunResult（缺 scenario_id）", path)
	}
	return &r, nil
}

// Markdown 渲染人类可读的 A/B 报告。
func (c *Comparison) Markdown() string {
	var b strings.Builder
	b.WriteString("# 评测 A/B 对比\n\n")
	b.WriteString(fmt.Sprintf("- Scenario: `%s` (%s)\n", c.ScenarioID, c.ScenarioName))
	b.WriteString(fmt.Sprintf("- Task: #%d → #%d\n", c.TaskA, c.TaskB))
	b.WriteString(fmt.Sprintf("- Pass: %s → %s", boolMark(c.PassBefore), boolMark(c.PassAfter)))
	switch {
	case c.Regressed:
		b.WriteString("  **❌ 退步**")
	case c.Improved:
		b.WriteString("  **✅ 提升**")
	}
	b.WriteString("\n\n## 指标变化\n\n")
	b.WriteString("| 指标 | Δ |\n|---|---:|\n")
	b.WriteString(fmt.Sprintf("| 必得项命中 | %+d |\n", c.RequiredFoundDelta))
	b.WriteString(fmt.Sprintf("| 额外发现 | %+d |\n", c.UnexpectedDelta))
	b.WriteString(fmt.Sprintf("| 证据完整度 | %+.1f%% |\n", c.EvidenceDelta*100))
	b.WriteString(fmt.Sprintf("| 阶段覆盖 | %+d |\n", c.StageDelta))
	b.WriteString(fmt.Sprintf("| Token | %+d |\n", c.TokensDelta))
	b.WriteString(fmt.Sprintf("| 成本 USD | %+.4f |\n", c.CostDeltaUSD))
	b.WriteString(fmt.Sprintf("| 耗时分钟 | %+.1f |\n", c.DurationDeltaMin))
	if len(c.NewlyMissing) > 0 {
		b.WriteString("\n## 新缺失\n\n")
		for _, x := range c.NewlyMissing {
			b.WriteString("- ❌ " + x + "\n")
		}
	}
	if len(c.NewlyFound) > 0 {
		b.WriteString("\n## 新命中\n\n")
		for _, x := range c.NewlyFound {
			b.WriteString("- ✅ " + x + "\n")
		}
	}
	return b.String()
}

func boolMark(v bool) string {
	if v {
		return "PASS"
	}
	return "FAIL"
}
