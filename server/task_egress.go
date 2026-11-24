package server

// 任务出口回执（issue #39）：任务构建 Agent bundle 时，把实际注入给
// worker/planner/mainagent 的出口配置做一次只读快照，持久化到
// tasks.egress_snapshot，并通过 GET /api/tasks/{id}/egress 暴露。
//
// 设计边界（硬约束）：
//   - 纯只读：采集复用 agentsForTask 已经算出的三次 ProxyAddr()/ProxyCACert()
//     返回值，绝不额外调用 ProxyAddr（那会推进 round_robin/random 的池游标，
//     改变三角色的出口分配）；唯一新增副作用是一次 UPDATE。
//   - 凭据零明文：地址在写入 DB 前结构化脱敏（只保留 scheme/host/port，
//     userinfo 直接丢弃，另给 has_auth 布尔）；解析失败不回显原文。
//   - 不撒谎：捕获开启时 Agent 出口只是本地 MITM 地址，真实上游由 MITM 逐请求
//     按目标 host 选择，构建期不可知实际出口 IP —— 回执只声明上游策略。
//   - UA 不是单值：按执行面列出「平台固定 / 运行时默认 / 工具自带」三类默认与
//     覆盖入口，并显式声明不代表目标侧实际收到的 User-Agent。

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
)

// 出口类型枚举。与 Manager.ProxyAddr() 的分支一一对应。
const (
	egressKindRecordingProxy = "recording_proxy" // 流量捕获开：本地记录代理（MITM）
	egressKindProxyPool      = "proxy_pool"      // 捕获关：注入代理池挑出的上游
	egressKindGlobalProxy    = "global_proxy"    // 捕获关：注入全局出口代理
	egressKindDirect         = "direct"          // 无代理：真实 IP 直连
	egressKindStrictBlock    = "strict_block"    // 严格出口哨兵：请求必然失败，绝不回退直连
)

const taskEgressSchemaVersion = 1

// TaskEgressSnapshot 是 tasks.egress_snapshot 的 JSON 形态。字段只增不改；
// 读取端按 schema_version 宽读。地址字段均已脱敏。
type TaskEgressSnapshot struct {
	SchemaVersion int                 `json:"schema_version"`
	Source        string              `json:"source"` // task_agent_build
	CapturedAt    string              `json:"captured_at"`
	BuildVersion  string              `json:"build_version,omitempty"`
	Capture       TaskEgressCapture   `json:"capture"`
	StrictEgress  bool                `json:"strict_egress"`
	Pool          TaskEgressPool      `json:"pool"`
	Upstream      *TaskEgressUpstream `json:"upstream,omitempty"` // 仅捕获开：MITM 上游策略
	Egress        TaskEgressRoute     `json:"egress"`             // worker 的实际出口（主展示值）
	Roles         []TaskEgressRole    `json:"roles"`              // 三个 Agent 各自的注入值
	RolesUniform  bool                `json:"roles_uniform"`
	Observed      TaskEgressObserved  `json:"observed"` // 实际出口 IP 构建期不可得
	Platform      TaskEgressPlatform  `json:"platform_surfaces"`
	UA            TaskEgressUA        `json:"ua"`
}

// TaskEgressPlatform 声明不在三角色 bundle 内的旁路执行面：它们的出口在
// **每次调用时**另行解析 Manager.ProxyAddr()（而不是构建期烤死），因此可能
// 与 roles 里的值不同（例如构建后运维改了池/全局代理/捕获开关）。回执不谎称
// 覆盖它们，只说明「同一判定树、实时取值」。
type TaskEgressPlatform struct {
	Surfaces []TaskEgressPlatformSurface `json:"surfaces"`
	Note     string                      `json:"note"`
}

type TaskEgressPlatformSurface struct {
	ID       string   `json:"id"`
	Scope    string   `json:"scope"`  // platform / external
	Egress   string   `json:"egress"` // live_proxy_addr：每次调用实时解析；固定记录代理等
	Override []string `json:"override,omitempty"`
	Note     string   `json:"note,omitempty"`
}

type TaskEgressCapture struct {
	Enabled   bool   `json:"enabled"`   // settings.traffic_capture（构建时）
	Injected  bool   `json:"injected"`  // 三个 Agent 真的被注入了记录代理地址（traffic 子系统存在）
	Effective bool   `json:"effective"` // 记录代理确实在监听（traffic.Running()）
	CAPresent bool   `json:"ca_present"`
	Note      string `json:"note,omitempty"`
}

type TaskEgressPool struct {
	Configured bool   `json:"configured"`
	Available  int    `json:"available"` // 构建时未被熔断的条目数
	Strategy   string `json:"strategy,omitempty"`
}

// TaskEgressEndpoint 是脱敏后的代理端点：只保留 scheme/host/port，userinfo
// 在解析后立即丢弃；ParseOK=false 表示地址不可解析（坏代理必失败，不能与
// 「直连」混淆）。Address 仅用于展示，由已脱敏字段重新合成。
type TaskEgressEndpoint struct {
	Scheme  string `json:"scheme,omitempty"`
	Host    string `json:"host,omitempty"`
	Port    string `json:"port,omitempty"`
	Address string `json:"address,omitempty"`
	HasAuth bool   `json:"has_auth"`
	ParseOK bool   `json:"parse_ok"`
}

type TaskEgressUpstream struct {
	Kind string `json:"kind"`
	TaskEgressEndpoint
	Note string `json:"note,omitempty"`
}

type TaskEgressRoute struct {
	Kind string `json:"kind"`
	TaskEgressEndpoint
}

// TaskEgressObserved 显式表达「构建期不可得」的事实，而不是静默省略：
// 捕获开启时 Agent 只连本地 MITM，真实出口 IP 由 MITM 逐请求选择，构建期
// 无法观测。真实 IP 级对账要等 exchanges.task_id（#25）。
type TaskEgressObserved struct {
	Known  bool   `json:"known"`
	Reason string `json:"reason,omitempty"`
}

type TaskEgressRole struct {
	Role string `json:"role"` // worker / planner / mainagent
	TaskEgressRoute
}

type TaskEgressUA struct {
	TaskLevelOverride string                `json:"task_level_override"` // none：任务级/全局均无目标 UA 配置
	Observation       string                `json:"observation"`         // declaration_only：声明而非实测
	Surfaces          []TaskEgressUASurface `json:"surfaces"`
	Note              string                `json:"note"`
}

type TaskEgressUASurface struct {
	ID       string   `json:"id"`
	Scope    string   `json:"scope"` // native / shell / platform / external
	Class    string   `json:"class"` // platform_fixed / runtime_default / tool_own
	Value    string   `json:"value,omitempty"`
	Note     string   `json:"note,omitempty"`
	Override []string `json:"override,omitempty"`
}

// taskEgressInput 是构建快照所需的全部只读输入。所有值都在 agentsForTask
// 装配时读取；CapturedAt 由调用方注入，便于测试固定时间。
type taskEgressInput struct {
	CapturedAt           time.Time
	BuildVersion         string
	CaptureEnabled       bool
	CaptureInjected      bool // ProxyAddr 返回了记录代理地址（traffic 存在且开关开）
	CaptureEffective     bool // 记录代理在监听（traffic.Running()）
	CAPresent            bool
	StrictEgress         bool
	DirectRecordFallback bool
	PoolConfigured       bool
	PoolAvailable        int
	PoolStrategy         string
	GlobalProxy          string            // 持久化配置值（捕获关闭时 Agent 直接注入它）
	MITMUpstream         string            // 捕获开启时 MITM 真正持有的上游（Traffic.UpstreamProxy）
	Roles                map[string]string // role → 实际注入的代理原始值（仅在本函数栈内使用）
}

// buildTaskEgressSnapshot 是纯函数：配置快照 → 回执字段。地址在构造 route
// 时立即脱敏，原始值不进入返回值。
func buildTaskEgressSnapshot(in taskEgressInput) TaskEgressSnapshot {
	snap := TaskEgressSnapshot{
		SchemaVersion: taskEgressSchemaVersion,
		Source:        "task_agent_build",
		CapturedAt:    in.CapturedAt.UTC().Format(time.RFC3339),
		BuildVersion:  in.BuildVersion,
		Capture: TaskEgressCapture{
			Enabled:   in.CaptureEnabled,
			Injected:  in.CaptureInjected,
			Effective: in.CaptureEffective,
			CAPresent: in.CAPresent,
			Note:      egressCaptureNote(in),
		},
		StrictEgress: in.StrictEgress,
		Pool: TaskEgressPool{
			Configured: in.PoolConfigured,
			Available:  in.PoolAvailable,
			Strategy:   in.PoolStrategy,
		},
		UA:       taskEgressUA(),
		Platform: taskEgressPlatform(),
		Observed: TaskEgressObserved{
			Known:  false,
			Reason: "not_observable_at_capture",
		},
	}
	for _, role := range []string{"worker", "planner", "mainagent"} {
		snap.Roles = append(snap.Roles, TaskEgressRole{
			Role:            role,
			TaskEgressRoute: classifyEgressRoute(in.Roles[role], in),
		})
	}
	snap.Egress = snap.Roles[0].TaskEgressRoute // worker 是目标流量的主执行面
	snap.RolesUniform = egressRolesUniform(snap.Roles)
	snap.Upstream = buildTaskEgressUpstream(in)
	return snap
}

func classifyEgressRoute(raw string, in taskEgressInput) TaskEgressRoute {
	// 注入的是记录代理地址（Manager.ProxyAddr 的捕获开分支）。注意这里看的是
	// 「是否注入」而不是「是否在监听」：监听失败时 Agent 手里仍是这个地址，
	// 回执应如实显示 recording_proxy，并由 capture.effective 说明未录制。
	if in.CaptureInjected {
		return newEgressRoute(egressKindRecordingProxy, raw)
	}
	if strings.TrimSpace(raw) == "" {
		return TaskEgressRoute{Kind: egressKindDirect, TaskEgressEndpoint: TaskEgressEndpoint{ParseOK: true}}
	}
	if raw == strictEgressBlockProxy {
		return TaskEgressRoute{Kind: egressKindStrictBlock, TaskEgressEndpoint: TaskEgressEndpoint{ParseOK: true}}
	}
	// 与 Manager.ProxyAddr（server/manager.go）的分支顺序保持一致：捕获关时
	// 先池（traffic 可用且池里有未熔断条目），再严格哨兵/全局代理，最后直连。
	// 池可用数 >0 说明本次调用走的是池分支。
	if in.PoolConfigured && in.PoolAvailable > 0 {
		return newEgressRoute(egressKindProxyPool, raw)
	}
	if strings.TrimSpace(in.GlobalProxy) != "" {
		return newEgressRoute(egressKindGlobalProxy, raw)
	}
	// 兜底：地址非空但既非哨兵也非全局代理——仍按池出口记录（不吞掉事实）。
	return newEgressRoute(egressKindProxyPool, raw)
}

func newEgressRoute(kind, raw string) TaskEgressRoute {
	return TaskEgressRoute{Kind: kind, TaskEgressEndpoint: redactEgressProxy(raw)}
}

func egressRolesUniform(roles []TaskEgressRole) bool {
	if len(roles) < 2 {
		return true
	}
	first := roles[0].TaskEgressRoute
	for _, r := range roles[1:] {
		if r.Kind != first.Kind || r.Scheme != first.Scheme || r.Host != first.Host ||
			r.Port != first.Port || r.HasAuth != first.HasAuth || r.ParseOK != first.ParseOK {
			return false
		}
	}
	return true
}

// egressCaptureNote 说清 capture 的边界：有效不等于「全部流量被录制」。
// MITM 对拦截失败的 host 会透明隧道放行（fail-open，见 traffic/traffic.go
// 的 pass 注释），这些 host 明确不产生录制。
func egressCaptureNote(in taskEgressInput) string {
	switch {
	case !in.CaptureEnabled:
		return ""
	case in.CaptureInjected && !in.CaptureEffective:
		return "记录代理地址已注入 Agent，但监听未就绪（端口占用或启动失败），目标流量实际不会被录制。"
	case in.CaptureEffective:
		return "记录代理监听正常。MITM 拦截失败的 host 会透明隧道（fail-open）放行且不产生录制，因此不代表全部目标流量被录制。"
	default:
		return "设置已开启，但记录代理不可用，实际未录制。"
	}
}

// buildTaskEgressUpstream 只描述「MITM 会按什么策略选上游」，不是实际出口 IP。
// 判定顺序与 traffic 的上游钩子一致：池 → 严格出口兜底 → 全局代理 → 直连
// （traffic/traffic.go 的 SetUpstreamProxy 回调）。
func buildTaskEgressUpstream(in taskEgressInput) *TaskEgressUpstream {
	if !in.CaptureInjected {
		return nil
	}
	up := &TaskEgressUpstream{Kind: egressKindDirect, TaskEgressEndpoint: TaskEgressEndpoint{ParseOK: true}}
	switch {
	case in.PoolConfigured && in.PoolAvailable > 0:
		up.Kind = egressKindProxyPool
		up.Note = "记录代理的上游：代理池（按目标 host 逐请求选择；构建期不可知实际出口 IP）"
	case in.StrictEgress && in.PoolConfigured:
		if in.DirectRecordFallback {
			up.Kind = egressKindDirect
			up.Note = "记录代理的上游：严格出口兜底直连（运维显式开启；是否录制仍取决于 MITM 是否成功拦截该 host）"
		} else {
			up.Kind = egressKindStrictBlock
			up.Note = "记录代理的上游：代理池全部熔断且严格出口开启，目标请求会快速失败（不回退直连）"
		}
	case strings.TrimSpace(in.MITMUpstream) != "":
		up.Kind = egressKindGlobalProxy
		up.TaskEgressEndpoint = redactEgressProxy(in.MITMUpstream)
		up.Note = "记录代理的上游：全局出口代理"
	default:
		up.Note = "记录代理的上游：直连（平台真实 IP；MITM 拦截失败的 host 透明隧道放行，不录制）"
	}
	return up
}

// redactEgressProxy 把代理地址结构化为 scheme/host/port + has_auth。
// 用户名/密码/路径/查询串/片段一律丢弃，展示串由已脱敏字段重新合成；
// 解析失败返回 ParseOK=false 的空端点，绝不回显原文。不要复用
// maskProxy/maskProxyURL：它们在解析失败时返回原始串，且后者保留用户名，
// 不满足 issue #39「用户名密码必须打码」。
func redactEgressProxy(raw string) TaskEgressEndpoint {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TaskEgressEndpoint{ParseOK: true}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return TaskEgressEndpoint{}
	}
	ep := TaskEgressEndpoint{
		Scheme:  u.Scheme,
		Host:    u.Hostname(),
		Port:    u.Port(),
		HasAuth: u.User != nil && u.User.String() != "",
		ParseOK: true,
	}
	// 只用结构化字段重建展示串；raw 的 path/query/fragment 从不参与。
	host := ep.Host
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	ep.Address = ep.Scheme + "://" + host
	if ep.Port != "" {
		ep.Address += ":" + ep.Port
	}
	return ep
}

// taskEgressPlatform 列出不在三角色 bundle 内的旁路执行面。它们不走构建期
// 注入的代理，而是在每次调用时重新解析 Manager.ProxyAddr()，所以回执的
// roles 不能代表它们；这里如实声明「实时取值」，不给出构建期快照值。
func taskEgressPlatform() TaskEgressPlatform {
	return TaskEgressPlatform{
		Note: "以下执行面不在 Agent bundle 内，出口在每次调用时实时解析 Manager.ProxyAddr()（同一判定树），因此可能与本回执记录的构建期值不同；同样可能被单次工具参数覆盖。",
		Surfaces: []TaskEgressPlatformSurface{
			{ID: "custom_http_tool", Scope: "platform", Egress: "live_proxy_addr", Override: []string{"proxy", "use_recording_proxy"},
				Note: "自定义 HTTP 工具：默认走平台出口（实时 ProxyAddr），可用 proxy 指定上游或 use_recording_proxy 强制记录代理"},
			{ID: "auth_check", Scope: "platform", Egress: "live_proxy_addr",
				Note: "任务登录自检：每次调用实时取 ProxyAddr + CA"},
			{ID: "enrich", Scope: "platform", Egress: "live_proxy_addr",
				Note: "资产自动补全：客户端按 proxy() 回调逐请求实时取值"},
			{ID: "chat_agent", Scope: "external", Egress: "live_proxy_addr",
				Note: "对话 Agent：构建时取一次 ProxyAddr，配置变更后重建"},
		},
	}
}

// taskEgressUA 是「默认 UA 与覆盖入口」的声明表。值为空表示运行时决定，
// 不能静态确定（例如 curl/<version>）。任何条目都不代表目标侧实际收到的头。
func taskEgressUA() TaskEgressUA {
	chrome := agent.DefaultTargetUserAgent
	return TaskEgressUA{
		TaskLevelOverride: "none",
		Observation:       "declaration_only",
		Note:              "仅声明平台默认值与覆盖入口；单次工具调用可覆盖，目标侧实际收到的 User-Agent 以流量记录为准。任务级与全局均无目标 UA 配置项。",
		Surfaces: []TaskEgressUASurface{
			{ID: "http_request", Scope: "native", Class: "platform_fixed", Value: chrome, Override: []string{"user_agent", "headers"}},
			{ID: "session_login", Scope: "native", Class: "platform_fixed", Value: chrome, Override: []string{"header"}},
			{ID: "js_audit", Scope: "native", Class: "platform_fixed", Value: chrome, Override: []string{"user_agent"}},
			{ID: "poc_scaffold", Scope: "native", Class: "platform_fixed", Value: chrome, Note: "脚本内固定，无覆盖入口"},
			{ID: "http_probe", Scope: "native", Class: "runtime_default", Note: "curl/<运行镜像版本>", Override: []string{"user_agent"}},
			{ID: "api_contract", Scope: "native", Class: "runtime_default", Note: "curl/<运行镜像版本>", Override: []string{"user_agent"}},
			{ID: "diff_responses", Scope: "native", Class: "runtime_default", Note: "curl/<运行镜像版本>", Override: []string{"user_agent", "header_a", "header_b"}},
			{ID: "scan_with_nuclei", Scope: "native", Class: "tool_own", Note: "nuclei 自带默认 UA，平台不覆盖"},
			{ID: "web_fetch", Scope: "native", Class: "tool_own", Value: "norma/0.4", Note: "SDK 固定值，平台不可配"},
			{ID: "bash_curl", Scope: "shell", Class: "runtime_default", Note: "curl/<运行镜像版本>"},
			{ID: "custom_http_tool", Scope: "platform", Class: "runtime_default", Note: "Go-http-client/1.1（HTTP/2 时 2.0）", Override: []string{"headers"}},
			{ID: "auth_check", Scope: "platform", Class: "runtime_default", Note: "Go-http-client/1.1", Override: []string{"headers"}},
			{ID: "enrich", Scope: "platform", Class: "platform_fixed", Value: chrome, Note: "资产自动补全（后台）"},
			{ID: "browser_mcp", Scope: "external", Class: "tool_own", Note: "Playwright 决定；默认未启用"},
		},
	}
}

// captureTaskEgress 在 Agent bundle 装配完成时构造快照。只读取装配期已经
// 发生的事实（三次实际注入值 + 当前出口策略），不发起任何额外的网络或池操作。
func (s *Server) captureTaskEgress(workerProxy, workerCA, plannerProxy, plannerCA, mainProxy, mainCA string) *TaskEgressSnapshot {
	if s == nil || s.m == nil {
		return nil
	}
	captureEnabled := s.m.TrafficEnabled()
	in := taskEgressInput{
		CapturedAt:     time.Now(),
		BuildVersion:   BuildVersion,
		CaptureEnabled: captureEnabled,
		CAPresent:      workerCA != "" || plannerCA != "" || mainCA != "",
		GlobalProxy:    s.m.GlobalProxy(),
		Roles: map[string]string{
			"worker":    workerProxy,
			"planner":   plannerProxy,
			"mainagent": mainProxy,
		},
	}
	if s.m.traffic != nil {
		in.CaptureInjected = captureEnabled
		// 仅当 Start 未返回（监听在服务）时才算「录制生效」；端口被占用等
		// 启动失败只会让 Start 立即返回，不得让 UI 谎称「录制中」。
		in.CaptureEffective = captureEnabled && s.m.traffic.Running()
		in.StrictEgress = s.m.traffic.StrictEgress()
		in.DirectRecordFallback = s.m.traffic.DirectRecordFallback()
		in.PoolConfigured = s.m.traffic.ProxyPoolConfigured()
		in.PoolAvailable = s.m.traffic.ProxyPoolAvailable()
		in.PoolStrategy = s.m.traffic.ProxyPoolStrategy()
		// 以 MITM 实际持有的上游为准：启动时被校验拒绝的全局代理从未存进
		// traffic.upstream，读持久化配置会把「直连」误报成「全局代理」。
		in.MITMUpstream = s.m.traffic.UpstreamProxy()
	}
	snap := buildTaskEgressSnapshot(in)
	return &snap
}

// persistTaskEgress 把构建时快照写入 tasks 行。必须在 taskAgentMu 释放后调用：
// 写入失败只记日志，不阻断装配、不影响任务执行。
func (s *Server) persistTaskEgress(t *Task, snap *TaskEgressSnapshot) {
	if s == nil || s.m == nil || s.m.pg == nil || t == nil || snap == nil {
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[egress] task %s 快照序列化失败: %v", t.ID, err)
		return
	}
	if err := s.m.pg.SetTaskEgressSnapshot(id, raw); err != nil {
		log.Printf("[egress] task %s 快照落库失败: %v", t.ID, err)
	}
}

// taskEgress 是只读端点：GET /api/tasks/{id}/egress。
//
//	404 = 任务不存在 / 已删除 / 已归档（与 GET /api/tasks/{id} 同一语义）
//	200 {built:false, reason:"not_built"} = 任务存在但尚未构建过 Agent
//	200 {built:true, snapshot:{...}}        = 构建时快照（非实时值）
func (s *Server) taskEgress(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	raw, found, err := pg.GetTaskEgressSnapshot(id)
	if err != nil {
		log.Printf("[egress] task %s 读取快照失败: %v", t.ID, err)
		writeErr(w, http.StatusInternalServerError, "读取出口回执失败")
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if len(raw) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"task_id": t.ID,
			"built":   false,
			"reason":  "not_built",
		})
		return
	}
	if !json.Valid(raw) {
		log.Printf("[egress] task %s 快照 JSON 非法", t.ID)
		writeErr(w, http.StatusInternalServerError, "出口回执数据损坏")
		return
	}
	// 宽读：只按 schema_version 判定能否理解。结构字段是「只增不改」，但若未来
	// 出现更高的主版本，前端不该拿一个它不认识的快照去渲染（缺字段会崩）。
	var head struct {
		SchemaVersion int    `json:"schema_version"`
		CapturedAt    string `json:"captured_at"`
		Egress        *struct {
			Kind string `json:"kind"`
		} `json:"egress"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Egress == nil || head.Egress.Kind == "" {
		log.Printf("[egress] task %s 快照缺少必需字段: %v", t.ID, err)
		writeJSON(w, http.StatusOK, map[string]any{
			"task_id":    t.ID,
			"built":      true,
			"compatible": false,
			"reason":     "malformed_snapshot",
		})
		return
	}
	if head.SchemaVersion != taskEgressSchemaVersion {
		log.Printf("[egress] task %s 快照 schema v%d，本端支持 v%d", t.ID, head.SchemaVersion, taskEgressSchemaVersion)
		writeJSON(w, http.StatusOK, map[string]any{
			"task_id":        t.ID,
			"built":          true,
			"compatible":     false,
			"reason":         "unsupported_schema_version",
			"schema_version": head.SchemaVersion,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":    t.ID,
		"built":      true,
		"compatible": true,
		"snapshot":   json.RawMessage(raw),
	})
}
