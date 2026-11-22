package server

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

// v0.4.92 预算硬化：nudge 带数字 / duration 维度 / hard 模式置位。

func int64p(v int64) *int { x := int(v); return &x }

// token 预算到顶：nudge 必须带已用/上限数字；hard 模式触发 onHard。
func TestIntentBudgetWatcherTokenNumbers(t *testing.T) {
	var steered string
	var hard atomic.Bool
	w := intentBudgetWatcher(intentBudgetConfig{Enabled: true, Tokens: 1000, Minutes: 0, HardMode: true},
		func(msg string) error { steered = msg; return nil },
		"test", time.Now(), func() { hard.Store(true) })
	if w == nil {
		t.Fatal("watcher 不应为 nil")
	}
	w(db.Activity{Kind: "usage", InputTokens: int64p(900)}) // 未到顶：不触发
	if steered != "" || hard.Load() {
		t.Fatal("未到顶不应触发")
	}
	w(db.Activity{Kind: "usage", InputTokens: int64p(1200)}) // 到顶
	if !strings.Contains(steered, "1200") || !strings.Contains(steered, "1000") {
		t.Fatalf("nudge 应带已用/上限数字: %q", steered)
	}
	if !hard.Load() {
		t.Fatal("hard 模式应触发 onHard")
	}
	// 二次 usage 不再重复 steer（一次为准）
	steered = ""
	w(db.Activity{Kind: "usage", InputTokens: int64p(2000)})
	if steered != "" {
		t.Fatalf("应只提醒一次: %q", steered)
	}
}

// 墙钟维度：startedAt 早于 minutes → steer + hard 置位。
func TestIntentBudgetWatcherDuration(t *testing.T) {
	var steered string
	var hard atomic.Bool
	w := intentBudgetWatcher(intentBudgetConfig{Enabled: true, Tokens: 0, Minutes: 5, HardMode: true},
		func(msg string) error { steered = msg; return nil },
		"test", time.Now().Add(-6*time.Minute), func() { hard.Store(true) })
	w(db.Activity{Kind: "usage", InputTokens: int64p(1)})
	if !strings.Contains(steered, "5 分钟") || !hard.Load() {
		t.Fatalf("墙钟预算应触发: %q hard=%v", steered, hard.Load())
	}
}

// soft 模式：到顶只 steer 不置位。
func TestIntentBudgetWatcherSoftMode(t *testing.T) {
	var hard atomic.Bool
	w := intentBudgetWatcher(intentBudgetConfig{Enabled: true, Tokens: 1000, HardMode: false},
		func(string) error { return nil }, "test", time.Now(), func() { hard.Store(true) })
	w(db.Activity{Kind: "usage", InputTokens: int64p(5000)})
	if hard.Load() {
		t.Fatal("soft 模式不应置位 hard")
	}
}

// hard 模式下 steerHooks 拦截非收尾工具（http_request），放行写回类（record_fact）。
func TestBudgetHardBlocksNonSettlementTools(t *testing.T) {
	var hard atomic.Bool
	hard.Store(true)
	h := steerHooks{
		budgetHard:    &hard,
		budgetLimit:   1000,
		budgetMinutes: 10,
		drain:         func() (string, bool) { return "", false },
	}
	blocked, msg, _ := h.PreToolUse(t.Context(), "http_request", []byte(`{}`))
	if !blocked || !strings.Contains(msg, "预算已耗尽") {
		t.Fatalf("hard 模式应拦截 http_request: blocked=%v msg=%q", blocked, msg)
	}
	blocked2, msg2, _ := h.PreToolUse(t.Context(), "record_fact", []byte(`{}`))
	if blocked2 {
		t.Fatalf("写回类应放行: %q", msg2)
	}
	// 未置位：不拦截
	h2 := h
	h2.budgetHard = &atomic.Bool{}
	if b, _, _ := h2.PreToolUse(t.Context(), "http_request", []byte(`{}`)); b {
		t.Fatal("未置位不应拦截")
	}
}
