package agent

import (
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestAuditFindingPayloadStrategies(t *testing.T) {
	f := &db.DBFinding{ID: 1, Severity: "high", Evidence: "GET /api/user?id=2 -> HTTP/1.1 200 OK, returned another user's phone 13800000000"}
	cases := []struct {
		name    string
		payload map[string]any
		traffic int
		want    string
	}{
		{"http_diff_pass", map[string]any{"verification_strategy": "http_diff"}, 2, "pass"},
		{"http_diff_fail", map[string]any{"verification_strategy": "http_diff"}, 0, "fail"},
		{"dual_identity_fail", map[string]any{"verification_strategy": "dual_identity"}, 0, "fail"},
		{"manual", map[string]any{"verification_strategy": "manual"}, 0, "needs_human"},
		{"unknown", map[string]any{"verification_strategy": "bogus"}, 0, "fail"},
	}
	for _, c := range cases {
		got := auditFindingPayload(f, c.payload, c.traffic)
		if got.Status != c.want {
			t.Errorf("%s: status=%s want %s (%+v)", c.name, got.Status, c.want, got)
		}
	}
}

func TestAuditFindingDualIdentity(t *testing.T) {
	f := &db.DBFinding{ID: 2, Severity: "high", Evidence: "账号A 请求返回 账号B 的订单列表；账号B token 对照 403"}
	got := auditFindingPayload(f, map[string]any{"verification_strategy": "dual_identity"}, 0)
	if got.Status != "pass" {
		t.Fatalf("dual identity audit = %+v", got)
	}
}

func TestAuditFindingEffectProof(t *testing.T) {
	short := &db.DBFinding{ID: 3, Evidence: "读取到数据"}
	if got := auditFindingPayload(short, map[string]any{"verification_strategy": "effect_proof"}, 0); got.Status != "fail" {
		t.Fatalf("short effect proof should fail: %+v", got)
	}
	long := &db.DBFinding{ID: 4, Evidence: "通过未授权接口分页读取到 5 条订单数据，包含订单号、收货人、手机号与金额；响应 200，字段完整。" +
		"随后用同一接口把 pageSize 调到 100，连续请求 3 页均返回 200，累计读取 287 条订单记录，" +
		"证明可批量读取非本人业务数据，影响范围覆盖该商户全部近期订单。"}
	if got := auditFindingPayload(long, map[string]any{"verification_strategy": "effect_proof"}, 0); got.Status != "pass" {
		t.Fatalf("long effect proof should pass: %+v", got)
	}
}

func TestDeriveVerificationStrategy(t *testing.T) {
	if got := deriveVerificationStrategy("anything", 2); got != "http_diff" {
		t.Fatalf("traffic pair -> %s", got)
	}
	if got := deriveVerificationStrategy("curl http://x/api -d id=2 返回 200 响应", 0); got != "poc_replay" {
		t.Fatalf("curl -> %s", got)
	}
	if got := deriveVerificationStrategy("???", 0); got != "manual" {
		t.Fatalf("unknown -> %s", got)
	}
}
