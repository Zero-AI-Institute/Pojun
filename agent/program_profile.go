package agent

// SRC/众测 program profile 的运行时支持（v0.4.112）。
//
// profile 是任务级元数据：平台/handle、公开 scope/excluded、允许的扫描器、
// 目标 RPS、dry-run/allow_race。它不是授权范围的替代品（真实范围仍由
// task_scope/task_constraints 决定），只做三件事：
//   1. 把 program 约束渲染进 planner/worker/mainagent 的 system prompt；
//   2. 给原生 HTTP 工具（http_request/session_login）注入 X-Bug-Bounty；
//   3. 对原生 HTTP 工具按 RPS 做进程内令牌桶限速；dry-run 拒绝 http_request 的
//      状态变更方法（session_login 仍允许，否则无法验证登录态）。
//
// Bash/MCP 不在这层硬限速/硬拦截范围内：它们没有统一的请求入口，做成只覆盖
// 一半的“硬边界”会误导人。提示词会明确说明这一点，避免宣称不存在的保证。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chu0119/pojun/db"
)

// ProgramProfileBlock 渲染 program profile 提示块；空 profile 返回空串，
// 保证未配置 profile 的任务提示词逐字不变。
func ProgramProfileBlock(p *db.ProgramProfile) string {
	if p == nil || p.IsZero() {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【SRC/众测 Program Profile（任务级元数据；不是授权范围的替代品）】")
	if p.Platform != "" || p.Handle != "" {
		b.WriteString("\n- Program: ")
		if p.Platform != "" {
			b.WriteString(p.Platform)
		}
		if p.Handle != "" {
			if p.Platform != "" {
				b.WriteString(" / ")
			}
			b.WriteString(p.Handle)
		}
	}
	if p.RPS > 0 {
		b.WriteString(fmt.Sprintf("\n- 目标速率上限：%.2f req/s（原生 http_request/session_login 已按此硬限速；Bash/MCP 不受硬限速，按同样节奏自律，不要突发）。", p.RPS))
	}
	if p.DryRun {
		b.WriteString("\n- **dry-run**：只做只读验证，不执行状态变更。原生 http_request 的 POST/PUT/PATCH/DELETE 会被拒绝（session_login 例外，用于建立会话）；Bash/MCP 不在硬拦截范围，必须自觉避免写/删/改。")
	}
	if p.AllowRace {
		b.WriteString("\n- 该 program 允许竞态/条件竞争类验证；仍要控制请求量并保留可复现证据。")
	} else {
		b.WriteString("\n- 未声明允许竞态：不要主动制造并发竞态或重复提交副作用请求。")
	}
	if len(p.Scope) > 0 {
		b.WriteString("\n- Program 公开 scope（仅作上下文，实际可测范围仍以 task_scope 为准）：")
		for i, s := range p.Scope {
			if i >= 30 {
				b.WriteString(fmt.Sprintf("\n  - …另有 %d 条（见任务 profile）", len(p.Scope)-i))
				break
			}
			b.WriteString("\n  - " + s)
		}
	}
	if len(p.Excluded) > 0 {
		b.WriteString("\n- **永不可测（excluded）**：")
		for i, s := range p.Excluded {
			if i >= 30 {
				b.WriteString(fmt.Sprintf("\n  - …另有 %d 条（见任务 profile）", len(p.Excluded)-i))
				break
			}
			b.WriteString("\n  - " + s)
		}
		b.WriteString("\n  即使 task_scope 里出现了匹配 excluded 的资产，也不得测试、不得为其派意图。")
	}
	if len(p.AllowedHosts) > 0 {
		b.WriteString("\n- 原生 HTTP 出口 allowlist（host）：" + strings.Join(p.AllowedHosts, ", ") +
			"；未列出的 host 会被硬拒绝（Bash/MCP 不在硬边界内）。")
	}
	if len(p.DeniedHosts) > 0 {
		b.WriteString("\n- 原生 HTTP 出口 denylist（host）：" + strings.Join(p.DeniedHosts, ", ") +
			"；deny 优先于 allow，命中即拒绝。")
	}
	if p.WindowStart != "" && p.WindowEnd != "" {
		tz := p.Timezone
		if tz == "" {
			tz = "服务器本地时区"
		}
		b.WriteString(fmt.Sprintf("\n- 允许测试时间窗：%s-%s（%s）；窗口外原生 HTTP 请求会被拒绝，Bash/MCP 仅提示自律。",
			p.WindowStart, p.WindowEnd, tz))
	}
	if p.MaxConcurrent > 0 {
		b.WriteString(fmt.Sprintf("\n- 原生 HTTP 并发上限：%d（超出会等待，不会丢弃请求）。", p.MaxConcurrent))
	}
	if len(p.ScannersAllowed) > 0 {
		b.WriteString("\n- 允许的扫描器/工具族：" + strings.Join(p.ScannersAllowed, ", ") +
			"；未列出的扫描器不要主动使用（手工 curl/单请求验证不受此限，但仍受速率与范围约束）。")
	}
	return b.String()
}

// ---- 原生 HTTP 出口硬边界（P2-4 第一批） ----

// hostMatchesPattern matches an exact host or a leading "*." wildcard. Host is
// already lowercased and port-stripped by the caller.
func hostMatchesPattern(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

func hostInList(host string, list []string) bool {
	for _, p := range list {
		if hostMatchesPattern(host, p) {
			return true
		}
	}
	return false
}

// checkProgramEgress applies the native-HTTP host allow/deny lists and the time
// window. It is called in doHTTP before any request bytes are sent. Empty
// profile fields mean “no restriction”.
func checkProgramEgress(host string, now time.Time, allowed, denied []string, start, end string, loc *time.Location) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return fmt.Errorf("目标 host 为空")
	}
	if hostInList(host, denied) {
		return fmt.Errorf("目标 host %s 命中 program denylist，已拒绝（原生 HTTP 硬边界）", host)
	}
	if len(allowed) > 0 && !hostInList(host, allowed) {
		return fmt.Errorf("目标 host %s 不在 program allowlist 内，已拒绝（原生 HTTP 硬边界）", host)
	}
	if start != "" && end != "" {
		if loc == nil {
			loc = time.Local
		}
		if !inTimeWindow(now.In(loc), start, end) {
			return fmt.Errorf("当前不在 program 允许的测试时间窗 %s-%s（%s），已拒绝原生 HTTP 请求", start, end, loc.String())
		}
	}
	return nil
}

// inTimeWindow supports overnight windows (start > end), e.g. 22:00-06:00.
// start == end is treated as all-day.
func inTimeWindow(now time.Time, start, end string) bool {
	st, err1 := time.Parse("15:04", start)
	et, err2 := time.Parse("15:04", end)
	if err1 != nil || err2 != nil {
		return true // 校验层已拒绝非法值；宁放行不误杀
	}
	cur := now.Hour()*60 + now.Minute()
	s := st.Hour()*60 + st.Minute()
	e := et.Hour()*60 + et.Minute()
	if s == e {
		return true
	}
	if s < e {
		return cur >= s && cur < e
	}
	return cur >= s || cur < e
}

type programSemaphore struct {
	mu  sync.Mutex
	ch  chan struct{}
	max int
}

var programSemaphores sync.Map // int64 taskID -> *programSemaphore

// acquireProgramSlot limits concurrent native-HTTP requests per task. It waits
// (respecting ctx) instead of dropping the request. max<=0 = no limit.
func acquireProgramSlot(ctx context.Context, taskID int64, max int) (func(), error) {
	if taskID <= 0 || max <= 0 {
		return func() {}, nil
	}
	v, _ := programSemaphores.LoadOrStore(taskID, &programSemaphore{})
	sem := v.(*programSemaphore)
	sem.mu.Lock()
	if sem.ch == nil || sem.max != max {
		sem.ch = make(chan struct{}, max)
		sem.max = max
	}
	ch := sem.ch
	sem.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- 进程内 RPS 令牌桶 ----

type programBucket struct {
	mu     sync.Mutex
	rps    float64
	tokens float64
	last   time.Time
}

var programBuckets sync.Map // int64 taskID -> *programBucket

// ConfigureProgramRPS updates the bucket for one task. rps<=0 removes the limit.
func ConfigureProgramRPS(taskID int64, rps float64) {
	if taskID <= 0 {
		return
	}
	if rps <= 0 {
		programBuckets.Delete(taskID)
		return
	}
	if v, ok := programBuckets.Load(taskID); ok {
		b := v.(*programBucket)
		b.mu.Lock()
		b.rps = rps
		b.last = time.Now()
		if b.tokens > 1 {
			b.tokens = 1
		}
		b.mu.Unlock()
		return
	}
	programBuckets.Store(taskID, &programBucket{rps: rps, tokens: 1, last: time.Now()})
}

// waitProgramRPS blocks until the task's next token is available. A missing
// bucket or rps<=0 returns immediately (zero behavior change).
func waitProgramRPS(ctx context.Context, taskID int64) error {
	if taskID <= 0 {
		return nil
	}
	v, ok := programBuckets.Load(taskID)
	if !ok {
		return nil
	}
	b := v.(*programBucket)
	for {
		b.mu.Lock()
		now := time.Now()
		if b.rps <= 0 {
			b.mu.Unlock()
			return nil
		}
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rps
			if b.tokens > 1 {
				b.tokens = 1
			}
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens -= 1
			b.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - b.tokens) / b.rps * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		b.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// isSafeHTTPMethod 用于 dry-run：只有这些方法不改变目标状态。
func isSafeHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// CheckProgramEgressProfile is the exported policy check used by server-side
// replay/regression checks. It applies the same deny/allow/window semantics as
// native HTTP tools; empty fields mean no restriction.
func CheckProgramEgressProfile(host string, p *db.ProgramProfile, now time.Time) error {
	if p == nil {
		return nil
	}
	loc := time.Local
	if strings.TrimSpace(p.Timezone) != "" {
		if l, err := time.LoadLocation(strings.TrimSpace(p.Timezone)); err == nil {
			loc = l
		}
	}
	return checkProgramEgress(host, now, p.AllowedHosts, p.DeniedHosts, p.WindowStart, p.WindowEnd, loc)
}
