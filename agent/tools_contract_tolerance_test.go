package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeToolInputWrapperAliasesAndScalars(t *testing.T) {
	raw := []byte(`{"finding":{"vulnerability":"sqli","risk":"高危","desc":"union sqli on /login","proof":{"status":200},"assets":12,"name":"SQLi"}}`)
	out, err := normalizeToolInput(raw, "finding")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["vulnclass"] != "注入" {
		t.Fatalf("vulnclass=%v", m["vulnclass"])
	}
	if m["severity"] != "high" {
		t.Fatalf("severity=%v", m["severity"])
	}
	if m["summary"] != "union sqli on /login" {
		t.Fatalf("summary=%v", m["summary"])
	}
	if ev, ok := m["evidence"].(string); !ok || !strings.Contains(ev, "status") {
		t.Fatalf("evidence=%v (%T)", m["evidence"], m["evidence"])
	}
	ids, ok := m["asset_ids"].([]any)
	if !ok || len(ids) != 1 {
		t.Fatalf("asset_ids=%#v", m["asset_ids"])
	}
	if f, ok := ids[0].(float64); !ok || f != 12 {
		t.Fatalf("asset_ids[0]=%#v (%T)", ids[0], ids[0])
	}
}

func TestNormalizeToolInputJSONString(t *testing.T) {
	raw := []byte(`"{\"data\":{\"description\":\"xss in search\",\"level\":\"中危\"}}"`)
	out, err := normalizeToolInput(raw, "data")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["summary"] != "xss in search" || m["severity"] != "medium" {
		t.Fatalf("m=%v", m)
	}
}

func TestNormalizeToolInputFactsAliases(t *testing.T) {
	raw := []byte(`{"fact":{"facts":[{"desc":"fingerprint nginx","detail_text":"nginx 1.25","assets":"3,4"}]}}`)
	out, err := normalizeToolInput(raw, "fact")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Facts []struct {
			Summary  string `json:"summary"`
			Detail   string `json:"detail"`
			AssetIDs []any  `json:"asset_ids"`
		} `json:"facts"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Facts) != 1 || m.Facts[0].Summary != "fingerprint nginx" || m.Facts[0].Detail != "nginx 1.25" {
		t.Fatalf("facts=%+v", m.Facts)
	}
	if len(m.Facts[0].AssetIDs) != 2 {
		t.Fatalf("asset_ids=%+v", m.Facts[0].AssetIDs)
	}
}

func TestNormalizeToolInputRejectsEmpty(t *testing.T) {
	if _, err := normalizeToolInput([]byte(`{}`), "finding"); err == nil {
		t.Fatal("empty object should fail")
	}
	if _, err := normalizeToolInput([]byte(`not json`), "finding"); err == nil {
		t.Fatal("non-JSON should fail")
	}
}

func TestDeriveVulnClass(t *testing.T) {
	cases := map[string]string{
		"union-based SQL 注入":      "注入",
		"reflected XSS in search": "XSS",
		"IDOR 读他人订单":              "未授权访问",
		"命令执行回显":                  "RCE",
		"文件上传绕过":                  "任意文件上传",
		"路径穿越读取/etc/passwd":       "任意文件读取",
	}
	for in, want := range cases {
		if got := deriveVulnClass(in); got != want {
			t.Errorf("deriveVulnClass(%q)=%q want %q", in, got, want)
		}
	}
}
