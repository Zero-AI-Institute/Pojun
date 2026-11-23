package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v0.4.99：miniapp_audit 只做路径校验与命令组装，扫描复用 js_audit.py 的 --dir 分支。
func TestMiniappAuditComposesCommand(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "miniapp", "wx1234567890abcdef", "source")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.miniappAudit()
	in, _ := json.Marshal(map[string]any{"dir": "miniapp/wx1234567890abcdef/source", "appid": "wx1234567890abcdef"})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out struct {
		RunWithBash string `json:"run_with_bash"`
		Out         string `json:"out"`
	}
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, toolResultText(t, res))
	}
	if !strings.Contains(out.RunWithBash, "js_audit.py") ||
		!strings.Contains(out.RunWithBash, "--dir") ||
		!strings.Contains(out.RunWithBash, "--out") ||
		!strings.Contains(out.RunWithBash, "--appid 'wx1234567890abcdef'") {
		t.Fatalf("command=%q", out.RunWithBash)
	}
	if !strings.Contains(out.Out, "miniapp-audit") {
		t.Fatalf("out=%q", out.Out)
	}
	if _, err := os.Stat(filepath.Join(dir, jsAuditScriptName)); err != nil {
		t.Fatalf("script missing: %v", err)
	}
}

func TestMiniappAuditRejectsOutsideTask(t *testing.T) {
	runDir := t.TempDir()
	outside := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(runDir)
	tool := ts.miniappAudit()
	in, _ := json.Marshal(map[string]any{"dir": outside})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(toolResultText(t, res), "超出任务目录范围") {
		t.Fatalf("expected boundary error, got: %s", toolResultText(t, res))
	}
}

func TestMiniappAuditRequiresRunDir(t *testing.T) {
	ts := NewToolSet(nil, "reporter")
	tool := ts.miniappAudit()
	in, _ := json.Marshal(map[string]any{"dir": "."})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.Contains(toolResultText(t, res), "未启用") {
		t.Fatalf("expected 未启用 error, got: %s", toolResultText(t, res))
	}
}

// 真正跑一遍 Python --dir 分支（无 python3 时跳过），验证输出契约。
func TestMiniappAuditDirScan(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(dir)
	tool := ts.miniappAudit()
	in, _ := json.Marshal(map[string]any{"dir": ".", "osv": false})
	if _, err := tool.Call(context.Background(), in, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	src := filepath.Join(dir, "miniapp", "source")
	if err := os.MkdirAll(filepath.Join(src, "pages", "index"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "app.json"), []byte(`{"pages":["pages/index/index"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	js := `wx.request({url:"https://api.example.com/api/v1/user/info"});
wx.cloud.init({env:"prod-1a2b3c"});
wx.cloud.callFunction({name:"adminDeleteUser"});
wx.cloud.database().collection("orders").get();
var appSecret = "0123456789abcdef0123456789abcdef";
var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz";
`
	if err := os.WriteFile(filepath.Join(src, "app-service.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "miniapp-audit")
	cmd := exec.Command(py, filepath.Join(dir, jsAuditScriptName), "--dir", src, "--out", out, "--no-osv")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python scan: %v\n%s", err, raw)
	}
	report, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatalf("report.json: %v\n%s", err, raw)
	}
	var r struct {
		Routes    []string `json:"routes"`
		Endpoints []struct {
			URL string `json:"url"`
		} `json:"endpoints"`
		Secrets []struct {
			Type string `json:"type"`
		} `json:"secrets"`
		Cloud struct {
			Env       []string `json:"env"`
			Functions []string `json:"functions"`
		} `json:"cloud"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(r.Routes) != 1 || r.Routes[0] != "pages/index/index" {
		t.Fatalf("routes=%v", r.Routes)
	}
	foundURL := false
	for _, e := range r.Endpoints {
		if strings.Contains(e.URL, "api.example.com") {
			foundURL = true
		}
	}
	if !foundURL {
		t.Fatalf("endpoints=%v", r.Endpoints)
	}
	if len(r.Cloud.Env) == 0 || len(r.Cloud.Functions) == 0 {
		t.Fatalf("cloud=%+v", r.Cloud)
	}
	foundSecret := false
	for _, s := range r.Secrets {
		if s.Type == "app_secret" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatalf("secrets=%v", r.Secrets)
	}
	if _, err := os.Stat(filepath.Join(out, "endpoints.txt")); err != nil {
		t.Fatalf("endpoints.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "secrets.txt")); err != nil {
		t.Fatalf("secrets.txt: %v", err)
	}
}
