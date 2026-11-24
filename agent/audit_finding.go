package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chu0119/pojun/db"

	actool "github.com/Autumn-27/norma/tool"
)

// VerificationAudit is the deterministic, read-only auditor result (v0.4.102).
// It is deliberately not an LLM self-assessment: the same evidence a reviewer
// would see is checked against the declared verification strategy.
type VerificationAudit struct {
	FindingID int64              `json:"finding_id"`
	Strategy  string             `json:"strategy"`
	Status    string             `json:"status"` // pass|fail|needs_human
	Checks    []VerificationStep `json:"checks,omitempty"`
	Missing   []string           `json:"missing,omitempty"`
	Note      string             `json:"note,omitempty"`
}

type VerificationStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass|fail|skip
	Detail string `json:"detail,omitempty"`
}

var verificationStrategies = map[string]bool{
	"http_diff": true, "dual_identity": true, "effect_proof": true,
	"poc_replay": true, "oracle": true, "manual": true,
}

// deriveVerificationStrategy picks a strategy from the evidence when the model
// omitted it. It is conservative: unknown → manual (needs human).
func deriveVerificationStrategy(evidence string, trafficCount int) string {
	if trafficCount >= 2 {
		return "http_diff"
	}
	low := strings.ToLower(evidence)
	switch {
	case containsAny(low, "oracle", "validator", "阴性", "对照组", "control group"):
		return "oracle"
	case containsAny(low, "账号a", "账号b", "用户a", "用户b", "双账号", "different user", "another account", "a/b"):
		return "dual_identity"
	case containsAny(low, "curl ", "sqlmap", "nuclei", "python ", "http_request", "payload") &&
		containsAny(low, "200", "响应", "回显", "output", "response"):
		return "poc_replay"
	case containsAny(low, "读取", "数据", "订单", "余额", "文件", "命令", "权限", "影响"):
		return "effect_proof"
	}
	return "manual"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// auditFindingPayload is pure and unit-tested. trafficCount is the number of
// bound traffic records (baseline+proof etc.).
func auditFindingPayload(f *db.DBFinding, payload map[string]any, trafficCount int) VerificationAudit {
	strategy := strings.ToLower(strings.TrimSpace(fmt.Sprint(payload["verification_strategy"])))
	if strategy == "<nil>" {
		strategy = ""
	}
	if strategy == "" {
		strategy = deriveVerificationStrategy(f.Evidence, trafficCount)
	}
	out := VerificationAudit{FindingID: f.ID, Strategy: strategy}
	add := func(name string, ok bool, detail string) {
		st := "pass"
		if !ok {
			st = "fail"
			out.Missing = append(out.Missing, name)
		}
		out.Checks = append(out.Checks, VerificationStep{Name: name, Status: st, Detail: detail})
	}
	add("evidence_present", strings.TrimSpace(f.Evidence) != "", "必须包含可核验的请求/响应或命令输出")
	switch strategy {
	case "http_diff":
		add("traffic_pair", trafficCount >= 2, fmt.Sprintf("需要至少 2 条流量（baseline+proof），当前 %d 条", trafficCount))
	case "dual_identity":
		add("dual_identity", containsAny(strings.ToLower(f.Evidence), "账号a", "账号b", "用户a", "用户b", "双账号", "different user", "another account", "a/b"),
			"需要 A/B 双身份对照（两个账号的请求/响应）")
	case "effect_proof":
		runes := len([]rune(strings.TrimSpace(f.Evidence)))
		add("impact_evidence", runes >= 120 && containsAny(strings.ToLower(f.Evidence), "读取", "数据", "订单", "余额", "文件", "命令", "权限", "影响"),
			fmt.Sprintf("需要可证明危害的影响证据（≥120 字且含影响字段），当前 %d 字", runes))
	case "poc_replay":
		low := strings.ToLower(f.Evidence)
		add("replayable_command", containsAny(low, "curl ", "sqlmap", "nuclei", "python ", "http_request", "payload") &&
			containsAny(low, "200", "响应", "回显", "output", "response"),
			"需要可重放的命令/请求与对应输出")
	case "oracle":
		add("oracle_evidence", containsAny(strings.ToLower(f.Evidence), "oracle", "validator", "阴性", "对照组", "control"),
			"需要 oracle/阴性对照结果")
	case "manual":
		out.Status = "needs_human"
		out.Note = "验证策略为 manual：需要人工复核证据"
		return out
	default:
		add("known_strategy", false, "未知策略；可选："+strings.Join([]string{"http_diff", "dual_identity", "effect_proof", "poc_replay", "oracle", "manual"}, "/"))
	}
	for _, c := range out.Checks {
		if c.Status == "fail" {
			out.Status = "fail"
			out.Note = "独立复核未通过：按 missing 补齐证据后再上报/出报告"
			return out
		}
	}
	out.Status = "pass"
	out.Note = "独立复核通过（确定性检查，不代表人工终审）"
	return out
}

// auditFindingTool is a read-only auditor available to planner/main agent (not
// worker): the worker that produced the finding should not be the only reviewer.
func (t *ToolSet) auditFindingTool() actool.CoreTool {
	return readTool(
		"audit_finding",
		"独立只读复核一个已登记漏洞（确定性，不调用模型、不改库）：读取 finding 证据与 verification_strategy，"+
			"检查是否满足对应策略（http_diff 需要 baseline+proof 两条流量；dual_identity 需要 A/B 双身份；"+
			"effect_proof 需要影响证据；poc_replay 需要可重放命令；oracle 需要对照结果）。"+
			"返回 pass/fail/needs_human + missing。critical/high 上报后、prove_goal/出报告前调用。",
		obj(map[string]any{"finding_id": idp("漏洞记录 ID（report_finding 返回的 finding_id）")}, "finding_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("audit_finding 需要任务上下文"), nil
			}
			var a struct {
				FindingID int64 `json:"finding_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.FindingID <= 0 {
				return actool.Errorf("finding_id 必须为正整数"), nil
			}
			f, err := t.ts.Finding(a.FindingID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if f == nil {
				return actool.Errorf(fmt.Sprintf("finding %d 不存在或不属于本任务", a.FindingID)), nil
			}
			if f.TaskID == nil || *f.TaskID != t.taskID {
				return actool.Errorf(fmt.Sprintf("finding %d 不属于当前任务，禁止跨任务复核", a.FindingID)), nil
			}
			var payload map[string]any
			if f.NodeID != nil {
				if n, err := t.ts.GetNode(*f.NodeID); err == nil && n != nil {
					_ = json.Unmarshal(n.Payload, &payload)
				}
			}
			audit := auditFindingPayload(f, payload, f.TrafficCount)
			return jsonResult(audit)
		})
}
