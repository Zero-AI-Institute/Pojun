package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/traffic"
)

func fixedEgressInput() taskEgressInput {
	return taskEgressInput{
		CapturedAt:       time.Date(2026, 11, 23, 12, 34, 56, 0, time.UTC),
		BuildVersion:     "0.4.98",
		CaptureEnabled:   true,
		CaptureInjected:  true,
		CaptureEffective: true,
		CAPresent:        true,
		PoolConfigured:   true,
		PoolAvailable:    2,
		PoolStrategy:     "round_robin",
		Roles: map[string]string{
			"worker":    "http://127.0.0.1:8788",
			"planner":   "http://127.0.0.1:8788",
			"mainagent": "http://127.0.0.1:8788",
		},
	}
}

func TestBuildTaskEgressSnapshotCaptureOn(t *testing.T) {
	snap := buildTaskEgressSnapshot(fixedEgressInput())
	if snap.SchemaVersion != 1 || snap.Source != "task_agent_build" {
		t.Fatalf("schema/source = %d/%q", snap.SchemaVersion, snap.Source)
	}
	if !snap.Capture.Enabled || !snap.Capture.Effective || !snap.Capture.CAPresent {
		t.Fatalf("capture 状态错误: %+v", snap.Capture)
	}
	if snap.Egress.Kind != egressKindRecordingProxy {
		t.Fatalf("worker kind = %q, want recording_proxy", snap.Egress.Kind)
	}
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindProxyPool {
		t.Fatalf("upstream = %+v, want proxy_pool", snap.Upstream)
	}
	if !snap.RolesUniform {
		t.Fatal("捕获开启时三角色应一致")
	}
	if got := snap.CapturedAt; got != "2026-11-23T12:34:56Z" {
		t.Fatalf("captured_at = %q", got)
	}
	if snap.Observed.Known || snap.Observed.Reason != "not_observable_at_capture" {
		t.Fatalf("observed = %+v, want explicit unknown", snap.Observed)
	}
}

// 捕获开关打开但 traffic 子系统不可用：不能冒充「已录制」，角色按捕获关闭的实际
// 注入值分类。
func TestBuildTaskEgressSnapshotCaptureDeclaredNotEffective(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = true
	in.CaptureInjected = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.Roles = map[string]string{"worker": "", "planner": "", "mainagent": ""}
	snap := buildTaskEgressSnapshot(in)
	if !snap.Capture.Enabled || snap.Capture.Effective {
		t.Fatalf("capture = %+v, want enabled && !effective", snap.Capture)
	}
	if snap.Egress.Kind != egressKindDirect {
		t.Fatalf("kind = %q, want direct", snap.Egress.Kind)
	}
	if snap.Upstream != nil {
		t.Fatalf("未生效的记录代理不应有 upstream: %+v", snap.Upstream)
	}
}

// 记录代理地址已注入但监听未就绪（端口占用/启动失败）：Agent 手里的出口仍是
// 记录代理地址，回执必须如实标 recording_proxy + effective=false，不能显示
// 「录制中」。这是 security 评审指出的「traffic != nil 就当成录制生效」缺口。
func TestBuildTaskEgressSnapshotInjectedNotListening(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureInjected = true
	in.CaptureEffective = false
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindRecordingProxy {
		t.Fatalf("kind = %q, want recording_proxy（注入的是记录代理地址）", snap.Egress.Kind)
	}
	if !snap.Capture.Enabled || !snap.Capture.Injected || snap.Capture.Effective {
		t.Fatalf("capture = %+v, want enabled && injected && !effective", snap.Capture)
	}
	if !strings.Contains(snap.Capture.Note, "监听未就绪") {
		t.Fatalf("capture note 未说明监听未就绪: %q", snap.Capture.Note)
	}
	if snap.Upstream == nil {
		t.Fatal("已注入记录代理时仍应声明上游策略")
	}
}

// 捕获开启 + 全局代理带凭据：upstream 必须结构化脱敏，序列化后无凭据。
func TestBuildTaskEgressUpstreamRedactsGlobalCredentials(t *testing.T) {
	in := fixedEgressInput()
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.GlobalProxy = "http://up-user:up-pass@10.0.0.9:3128"
	in.MITMUpstream = "http://up-user:up-pass@10.0.0.9:3128"
	snap := buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindGlobalProxy {
		t.Fatalf("upstream = %+v, want global_proxy", snap.Upstream)
	}
	if snap.Upstream.Address != "http://10.0.0.9:3128" || !snap.Upstream.HasAuth {
		t.Fatalf("upstream 未脱敏: %+v", snap.Upstream)
	}
	blob, _ := json.Marshal(snap)
	for _, banned := range []string{"up-user", "up-pass", "up-user:up-pass"} {
		if strings.Contains(string(blob), banned) {
			t.Fatalf("快照序列化泄漏上游凭据 %q: %s", banned, blob)
		}
	}
}

// 持久化的全局代理在启动时校验失败（MITM 实际直连）：回执必须按真实上游
// 报 direct，不能把一份从未生效的配置说成「全局出口代理」。
func TestBuildTaskEgressUpstreamUsesMITMValueNotPersistedSetting(t *testing.T) {
	in := fixedEgressInput()
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.GlobalProxy = "http://bad proxy" // 设置里残留的非法值
	in.MITMUpstream = ""                // traffic 从未装载它
	snap := buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindDirect {
		t.Fatalf("upstream = %+v, want direct（MITM 实际直连）", snap.Upstream)
	}
}

func TestBuildTaskEgressSnapshotPoolRolesDiverge(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureInjected = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.Roles = map[string]string{
		"worker":    "http://alice:s3cr3t@10.0.0.5:8080",
		"planner":   "http://bob@10.0.0.6:8080",
		"mainagent": "socks5://10.0.0.7:1080",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.RolesUniform {
		t.Fatal("三个不同上游应标记 roles_uniform=false")
	}
	if snap.Egress.Kind != egressKindProxyPool || !snap.Egress.HasAuth {
		t.Fatalf("worker route = %+v", snap.Egress)
	}
	if snap.Egress.Address != "http://10.0.0.5:8080" {
		t.Fatalf("worker address 未脱敏: %q", snap.Egress.Address)
	}
	blob, _ := json.Marshal(snap)
	for _, banned := range []string{"alice", "bob", "s3cr3t"} {
		if strings.Contains(string(blob), banned) {
			t.Fatalf("快照泄漏凭据片段 %q: %s", banned, blob)
		}
	}
}

func TestBuildTaskEgressSnapshotStrictBlock(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureInjected = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = true
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.GlobalProxy = ""
	in.Roles = map[string]string{
		"worker": strictEgressBlockProxy, "planner": strictEgressBlockProxy, "mainagent": strictEgressBlockProxy,
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindStrictBlock {
		t.Fatalf("kind = %q, want strict_block", snap.Egress.Kind)
	}
	if snap.Egress.Address != "" {
		t.Fatalf("严格阻断不应展示哨兵地址: %q", snap.Egress.Address)
	}
}

func TestBuildTaskEgressSnapshotGlobalAndDirect(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureInjected = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.GlobalProxy = "http://user:pw@10.0.0.9:3128"
	in.Roles = map[string]string{
		"worker": "http://user:pw@10.0.0.9:3128", "planner": "http://user:pw@10.0.0.9:3128", "mainagent": "http://user:pw@10.0.0.9:3128",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindGlobalProxy || !snap.Egress.HasAuth || snap.Egress.Address != "http://10.0.0.9:3128" {
		t.Fatalf("global route = %+v", snap.Egress)
	}

	in.GlobalProxy = ""
	in.Roles = map[string]string{"worker": "", "planner": "", "mainagent": ""}
	snap = buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindDirect || snap.Egress.Address != "" {
		t.Fatalf("direct route = %+v", snap.Egress)
	}
}

// 捕获开 + 池全熔断 + 严格出口 + 直连兜底：上游是直连（仍录制），不是严格阻断。
func TestBuildTaskEgressUpstreamStrictFallback(t *testing.T) {
	in := fixedEgressInput()
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.DirectRecordFallback = true
	snap := buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindDirect {
		t.Fatalf("upstream = %+v, want direct", snap.Upstream)
	}
	in.DirectRecordFallback = false
	snap = buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindStrictBlock {
		t.Fatalf("upstream = %+v, want strict_block", snap.Upstream)
	}
}

func TestBuildTaskEgressSnapshotGlobalWithExhaustedPoolStrict(t *testing.T) {
	// 捕获关闭 + 严格出口 + 池全熔断 + 有全局代理：Agent 侧仍走全局代理
	// （ProxyAddr 的严格分支只在没有全局代理时才返回哨兵）。
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureInjected = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = true
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.GlobalProxy = "http://10.0.0.9:3128"
	in.Roles = map[string]string{
		"worker": "http://10.0.0.9:3128", "planner": "http://10.0.0.9:3128", "mainagent": "http://10.0.0.9:3128",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindGlobalProxy {
		t.Fatalf("kind = %q, want global_proxy", snap.Egress.Kind)
	}
	if snap.Upstream != nil {
		t.Fatalf("捕获关闭不应有 upstream: %+v", snap.Upstream)
	}

	// 捕获开启时同样的策略组合：MITM 钩子在严格分支直接返回哨兵，
	// 即使配置了全局代理也不会回退到它。
	in.CaptureEffective = true
	in.CaptureInjected = true
	in.CAPresent = true
	in.Roles = map[string]string{
		"worker": "http://127.0.0.1:8788", "planner": "http://127.0.0.1:8788", "mainagent": "http://127.0.0.1:8788",
	}
	snap = buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindStrictBlock {
		t.Fatalf("upstream = %+v, want strict_block", snap.Upstream)
	}
}

func TestRedactEgressProxy(t *testing.T) {
	cases := []struct {
		raw      string
		wantAddr string
		wantHost string
		wantPort string
		wantAuth bool
		wantOK   bool
	}{
		{"http://alice:s3cr3t@10.0.0.1:8080", "http://10.0.0.1:8080", "10.0.0.1", "8080", true, true},
		{"socks5h://bob@[::1]:1080", "socks5h://[::1]:1080", "::1", "1080", true, true},
		{"http://user:pass@host:1/path?token=abc#frag", "http://host:1", "host", "1", true, true},
		{"http://10.0.0.1:8080", "http://10.0.0.1:8080", "10.0.0.1", "8080", false, true},
		{"http://proxy.example", "http://proxy.example", "proxy.example", "", false, true},
		{"", "", "", "", false, true},
		{"://bad", "", "", "", false, false},
		{"not a url", "", "", "", false, false},
	}
	for _, c := range cases {
		ep := redactEgressProxy(c.raw)
		if ep.Address != c.wantAddr || ep.Host != c.wantHost || ep.Port != c.wantPort ||
			ep.HasAuth != c.wantAuth || ep.ParseOK != c.wantOK {
			t.Fatalf("redactEgressProxy(%q) = %+v, want addr=%q host=%q port=%q auth=%v ok=%v",
				c.raw, ep, c.wantAddr, c.wantHost, c.wantPort, c.wantAuth, c.wantOK)
		}
		for _, banned := range []string{"alice", "bob", "s3cr3t", "pass", "token=abc", "not a url", "/path"} {
			if strings.Contains(ep.Address, banned) {
				t.Fatalf("输出泄漏 %q: %q", banned, ep.Address)
			}
		}
		// 整结构序列化后同样不得出现凭据片段（防止新增字段带出原文）。
		blob, _ := json.Marshal(ep)
		for _, banned := range []string{"alice", "bob", "s3cr3t", "token=abc", "not a url", "/path"} {
			if strings.Contains(string(blob), banned) {
				t.Fatalf("结构序列化泄漏 %q: %s", banned, blob)
			}
		}
	}
}

// 回归守卫：agentsForTask 必须保持三次 ProxyAddr()/ProxyCACert() 调用
// （worker/planner/mainagent 各一次）。新增第四次会推进 round_robin/random
// 的池游标，改变三角色实际拿到的出口分配，属于行为回归。
func TestAgentsForTaskCallsProxyAddrExactlyThreeTimes(t *testing.T) {
	src, err := os.ReadFile("task_llm.go")
	if err != nil {
		t.Fatalf("读 task_llm.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *Server) agentsForTask(")
	if start < 0 {
		t.Fatal("找不到 agentsForTask")
	}
	body = body[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end+2] // 函数体结束（顶层 } 顶格）
	}
	if got := strings.Count(body, "s.m.ProxyAddr()"); got != 3 {
		t.Fatalf("agentsForTask 内 ProxyAddr() 调用 %d 次，必须恰好 3 次", got)
	}
	if got := strings.Count(body, "s.m.ProxyCACert()"); got != 3 {
		t.Fatalf("agentsForTask 内 ProxyCACert() 调用 %d 次，必须恰好 3 次", got)
	}
}

// newEgressTestTraffic 打开一个真实的 traffic 实例（不启动监听），用于与
// Manager.ProxyAddr 对拍以及验证 Running() 语义。
func newEgressTestTraffic(t *testing.T) *traffic.Traffic {
	t.Helper()
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open traffic: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// 与真实 Manager.ProxyAddr() 对拍：分类必须和实际注入值一致，而不只是
// 「调用次数=3」。手工复刻判定树的风险是上游改了分支顺序后回执静默说谎，
// 这个测试用真实池/熔断/全局代理状态跑一遍，把分类钉在真实行为上。
func TestClassifyEgressRouteMatchesProxyAddr(t *testing.T) {
	const (
		poolURL   = "http://pool-user:pool-pass@10.0.0.5:8080"
		globalURL = "http://global-user:global-pass@10.0.0.9:3128"
	)
	pool := []traffic.PoolEntry{{URL: poolURL, Name: "p1", Enabled: true, Weight: 1}}
	cases := []struct {
		name       string
		captureOn  bool
		pool       []traffic.PoolEntry
		markBad    bool
		strict     bool
		fallback   bool
		global     string
		wantKind   string
		wantNoAddr bool
	}{
		{name: "capture_on", captureOn: true, pool: pool, wantKind: egressKindRecordingProxy},
		{name: "pool", pool: pool, wantKind: egressKindProxyPool},
		{name: "global", global: globalURL, wantKind: egressKindGlobalProxy},
		{name: "direct", wantKind: egressKindDirect, wantNoAddr: true},
		{name: "pool_broken_not_strict", pool: pool, markBad: true, wantKind: egressKindDirect, wantNoAddr: true},
		{name: "strict_no_global", pool: pool, markBad: true, strict: true, wantKind: egressKindStrictBlock, wantNoAddr: true},
		{name: "strict_with_global", pool: pool, markBad: true, strict: true, global: globalURL, wantKind: egressKindGlobalProxy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := newEgressTestTraffic(t)
			if len(c.pool) > 0 {
				if err := tr.SetProxyPool(c.pool, "sticky_host"); err != nil {
					t.Fatalf("set pool: %v", err)
				}
				if c.markBad {
					tr.ProxyPoolMarkBad(c.pool[0].URL, time.Hour)
				}
			}
			tr.SetStrictEgress(c.strict)
			tr.SetDirectRecordFallback(c.fallback)
			if c.global != "" {
				if err := tr.SetUpstreamProxy(c.global); err != nil {
					t.Fatalf("set upstream: %v", err)
				}
			}
			m := &Manager{traffic: tr, trafficOn: c.captureOn, globalProxy: c.global}

			addr := m.ProxyAddr() // 真实判定树
			if c.captureOn && addr != tr.ProxyAddr() {
				t.Fatalf("捕获开时 ProxyAddr = %q, want 记录代理 %q", addr, tr.ProxyAddr())
			}
			in := taskEgressInput{
				CaptureEnabled:       c.captureOn,
				CaptureInjected:      c.captureOn,
				CaptureEffective:     false, // 未启动监听；本测试只校验分类
				StrictEgress:         tr.StrictEgress(),
				DirectRecordFallback: tr.DirectRecordFallback(),
				PoolConfigured:       tr.ProxyPoolConfigured(),
				PoolAvailable:        tr.ProxyPoolAvailable(),
				PoolStrategy:         tr.ProxyPoolStrategy(),
				GlobalProxy:          c.global,
				MITMUpstream:         tr.UpstreamProxy(),
				Roles:                map[string]string{"worker": addr, "planner": addr, "mainagent": addr},
			}
			snap := buildTaskEgressSnapshot(in)
			if snap.Egress.Kind != c.wantKind {
				t.Fatalf("ProxyAddr=%q 分类为 %q, want %q", addr, snap.Egress.Kind, c.wantKind)
			}
			if c.wantNoAddr && snap.Egress.Address != "" {
				t.Fatalf("无代理场景不应展示地址: %q", snap.Egress.Address)
			}
			if !c.wantNoAddr && snap.Egress.Address == "" {
				t.Fatalf("有代理场景地址为空（addr=%q）", addr)
			}
			blob, _ := json.Marshal(snap)
			for _, banned := range []string{"pool-user", "pool-pass", "global-user", "global-pass"} {
				if strings.Contains(string(blob), banned) {
					t.Fatalf("快照泄漏凭据 %q: %s", banned, blob)
				}
			}
		})
	}
}

// capture.effective 必须反映真实监听，而不是「traffic 对象存在」。
func TestCaptureTaskEgressReflectsListenerLiveness(t *testing.T) {
	tr := newEgressTestTraffic(t)
	m := &Manager{traffic: tr, trafficOn: true}
	s := &Server{m: m}

	snap := s.captureTaskEgress(tr.ProxyAddr(), tr.CACertPath(), tr.ProxyAddr(), tr.CACertPath(), tr.ProxyAddr(), tr.CACertPath())
	if snap == nil {
		t.Fatal("captureTaskEgress = nil")
	}
	if !snap.Capture.Enabled || !snap.Capture.Injected || snap.Capture.Effective {
		t.Fatalf("未启动监听时 capture = %+v, want enabled && injected && !effective", snap.Capture)
	}

	done := make(chan error, 1)
	go func() { done <- tr.Start() }()
	deadline := time.Now().Add(10 * time.Second)
	for !tr.Running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tr.Running() {
		t.Fatal("记录代理未在 10s 内进入运行状态")
	}
	snap = s.captureTaskEgress(tr.ProxyAddr(), tr.CACertPath(), tr.ProxyAddr(), tr.CACertPath(), tr.ProxyAddr(), tr.CACertPath())
	if !snap.Capture.Effective {
		t.Fatalf("监听中就应 effective: %+v", snap.Capture)
	}
	if !strings.Contains(snap.Capture.Note, "透明隧道") {
		t.Fatalf("capture note 未说明 passthrough 盲区: %q", snap.Capture.Note)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("close traffic: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close 后 Start 未返回")
	}
	if tr.Running() {
		t.Fatal("Close 后 Running 仍为 true")
	}
}

func TestTaskEgressPlatformSurfaces(t *testing.T) {
	p := taskEgressPlatform()
	if len(p.Surfaces) == 0 || p.Note == "" {
		t.Fatal("旁路执行面声明为空")
	}
	byID := map[string]TaskEgressPlatformSurface{}
	for _, s := range p.Surfaces {
		byID[s.ID] = s
	}
	for _, id := range []string{"custom_http_tool", "auth_check", "enrich"} {
		s, ok := byID[id]
		if !ok || s.Egress != "live_proxy_addr" {
			t.Fatalf("%s = %+v, want live_proxy_addr", id, s)
		}
	}
}

func TestTaskEgressUA(t *testing.T) {
	ua := taskEgressUA()
	if ua.TaskLevelOverride != "none" || ua.Observation != "declaration_only" {
		t.Fatalf("ua 语义 = %q/%q", ua.TaskLevelOverride, ua.Observation)
	}
	if len(ua.Surfaces) == 0 {
		t.Fatal("UA 声明表为空")
	}
	byID := map[string]TaskEgressUASurface{}
	for _, s := range ua.Surfaces {
		byID[s.ID] = s
	}
	if got := byID["http_request"]; got.Class != "platform_fixed" || got.Value == "" {
		t.Fatalf("http_request = %+v", got)
	}
	for _, id := range []string{"http_probe", "api_contract", "diff_responses"} {
		got := byID[id]
		if got.Class != "runtime_default" {
			t.Fatalf("%s class = %q, want runtime_default", id, got.Class)
		}
		if got.Value != "" {
			t.Fatalf("%s 不应声明固定 UA: %q", id, got.Value)
		}
	}
}

// Handler 语义：401/404/200 built=false/200 built=true；快照原样透传。
func TestTaskEgressHandler(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	task, err := m.CreateTask("egress handler", "goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	do := func(path, token string) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, _ := do("/api/tasks/"+task.ID+"/egress", ""); code != http.StatusUnauthorized {
		t.Fatalf("no auth code = %d, want 401", code)
	}
	if code, _ := do("/api/tasks/999999999/egress", tok); code != http.StatusNotFound {
		t.Fatalf("unknown task code = %d, want 404", code)
	}
	code, out := do("/api/tasks/"+task.ID+"/egress", tok)
	if code != http.StatusOK || out["built"] != false || out["reason"] != "not_built" {
		t.Fatalf("not-built response = %d %v", code, out)
	}

	snap := buildTaskEgressSnapshot(taskEgressInput{
		CapturedAt:       time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
		CaptureEnabled:   false,
		CaptureEffective: false,
		Roles: map[string]string{
			"worker":    "http://user:pw@10.0.0.5:8080",
			"planner":   "http://user:pw@10.0.0.5:8080",
			"mainagent": "http://user:pw@10.0.0.5:8080",
		},
		PoolConfigured: true,
		PoolAvailable:  1,
		PoolStrategy:   "sticky_host",
	})
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := m.pg.SetTaskEgressSnapshot(taskID, raw); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	code, out = do("/api/tasks/"+task.ID+"/egress", tok)
	if code != http.StatusOK || out["built"] != true {
		t.Fatalf("built response = %d %v", code, out)
	}
	snapshot, _ := out["snapshot"].(map[string]any)
	egress, _ := snapshot["egress"].(map[string]any)
	if egress["kind"] != "proxy_pool" || egress["address"] != "http://10.0.0.5:8080" {
		t.Fatalf("egress = %v", egress)
	}
	body, _ := json.Marshal(out)
	if bytes.Contains(body, []byte("user:pw")) || bytes.Contains(body, []byte("pw@")) {
		t.Fatalf("响应泄漏代理凭据: %s", body)
	}
}
