package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// 覆盖矩阵缺口提醒（v0.4.100 重写）。
//
// 旧实现（v0.4.63）用 6 类关键词正则扫意图文本，和 planner prompt 的 10 类清单、
// graph_overview 的“被 fact 碰过的资产占比”是三套互不一致的口径。现在统一到
// agent.CoverageMatrix（asset × dimension）：引擎只在矩阵里挑“未测数量最多、
// 价值最高”的 1–2 个格子提醒，点名资产样本与维度打法。
//
// 每格每任务 6 小时内只提醒一次；任务意图太少（<5）时不提醒。
const coverageNudgeThrottle = 6 * time.Hour

func (e *Engine) nudgeCoverageGaps(t *Task) {
	if e.m.pg == nil || t == nil || t.Store == nil || e.m.assets == nil {
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 1000)
	if err != nil || len(intents) < 5 {
		// 意图太少（刚开局/测试场景）时先不谈覆盖缺口。
		return
	}
	tid, _ := strconv.ParseInt(t.ID, 10, 64)
	if tid <= 0 {
		return
	}
	m := agent.CoverageMatrixForTask(e.m.assets, t.Store, tid)
	if m == nil || m.Assets == 0 {
		return
	}
	nudged := 0
	for _, gap := range m.TopGaps {
		if nudged >= 2 {
			break
		}
		if gap.Untested < 2 || gap.Dimension == "" || gap.Dimension == "other" {
			continue
		}
		settingKey := fmt.Sprintf("coverage_nudge_%s_%s_%s", t.ID, gap.Dimension, gap.AssetType)
		if v, ok, _ := e.m.pg.GetSetting(settingKey); ok {
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < coverageNudgeThrottle {
				continue
			}
		}
		samples := strings.Join(gap.Samples, "、")
		if samples == "" {
			samples = "（用 list_untested_assets 查看样本）"
		}
		msg := fmt.Sprintf("覆盖矩阵缺口：%s 类资产有 %d 个尚未测试【%s】。建议对 %s 派 1 条该类意图——%s "+
			"summary 写清目标 endpoint、工具与判据；若该类对本目标明确不适用，派一条极小确认意图或用 fact 说明不适用，不要静默跳过。",
			gap.AssetType, gap.Untested, agent.DimensionLabel(gap.Dimension), samples, agent.DimensionTip(gap.Dimension))
		t.trigMu.Lock()
		t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "coverage_gap", Detail: msg})
		t.trigMu.Unlock()
		_ = e.m.pg.SetSetting(settingKey, strconv.FormatInt(time.Now().Unix(), 10))
		log.Printf("[coverage] task %s 缺口提醒：%s×%s 未测 %d", t.ID, gap.AssetType, gap.Dimension, gap.Untested)
		nudged++
	}
	if nudged > 0 {
		t.Notify()
	}
}
