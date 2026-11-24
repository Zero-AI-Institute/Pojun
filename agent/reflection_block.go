package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chu0119/pojun/db"
)

// recentLessonsBlock injects the most relevant terminal lessons into the
// worker's system prompt (v0.4.100). Relevance = same dimension first, then
// overlapping assets; newest wins within the same score. This is deterministic
// and cheap (one indexed query), not an LLM reflection.
func recentLessonsBlock(ts *db.ExplorationStore, intent *db.Node, limit int) string {
	if ts == nil || intent == nil || limit <= 0 {
		return ""
	}
	var p struct {
		Dimension string  `json:"dimension"`
		Summary   string  `json:"summary"`
		Title     string  `json:"title"`
		AssetIDs  []int64 `json:"asset_ids"`
	}
	_ = json.Unmarshal(intent.Payload, &p)
	summary := p.Summary
	if summary == "" {
		summary = p.Title
	}
	dim := IntentDimension(p.Dimension, summary)
	if dim == "" {
		dim = dimOther
	}
	if len(p.AssetIDs) == 0 && len(intent.Anchors) > 0 {
		p.AssetIDs = intent.Anchors
	}
	assetSet := map[int64]bool{}
	for _, id := range p.AssetIDs {
		assetSet[id] = true
	}

	items, err := ts.RecentReflections(60)
	if err != nil || len(items) == 0 {
		return ""
	}
	type scored struct {
		r     db.IntentReflection
		score int
	}
	var picked []scored
	for _, r := range items {
		score := 0
		if r.Dimension == dim {
			score += 3
		}
		for _, id := range r.AssetIDs {
			if assetSet[id] {
				score += 2
				break
			}
		}
		if score == 0 {
			continue
		}
		picked = append(picked, scored{r: r, score: score})
	}
	if len(picked) == 0 {
		return ""
	}
	// stable by score desc then id desc (newest)
	for i := 0; i < len(picked); i++ {
		for j := i + 1; j < len(picked); j++ {
			if picked[j].score > picked[i].score ||
				(picked[j].score == picked[i].score && picked[j].r.ID > picked[i].r.ID) {
				picked[i], picked[j] = picked[j], picked[i]
			}
		}
	}
	if len(picked) > limit {
		picked = picked[:limit]
	}
	var b strings.Builder
	b.WriteString("\n\n【同方向历史经验（引擎在终态自动沉淀；先看再动手，避免重复失败打法）】")
	for _, s := range picked {
		r := s.r
		fmt.Fprintf(&b, "\n- #%d [%s %s/%s] 写回 %d（事实/资产/漏洞合计），工具 %d 次/错误 %d 次：%s",
			r.IntentID, DimensionLabel(r.Dimension), r.TerminalState,
			shortReason(r.TerminalReason), r.WroteBack, r.ToolCalls, r.ToolErrors, firstLine(r.Lesson, 220))
	}
	return b.String()
}

func shortReason(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if i := strings.IndexAny(s, ":： "); i > 0 {
		s = s[:i]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
