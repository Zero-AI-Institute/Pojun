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

// v0.4.99 端到端：合成加密 wxapkg → miniapp_unpack.sh 解包 → 内嵌 Python --dir 审计。
// 跳过条件：没有 python3 / bash（CI Linux 正常都有）。
func TestMiniProgramEndToEnd(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	runDir := filepath.Join(root, "tasks", "1", "i1")
	uploads := filepath.Join(root, "tasks", "1", "uploads")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	scripts, err := filepath.Abs(filepath.Join("..", "skills", "mini-program", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(uploads, "__APP__.wxapkg")
	appid := "wx1234567890abcdef"
	fixture := exec.Command(py, filepath.Join(scripts, "wxapkg_fixture.py"),
		"--out", pkg, "--sample", "--encrypt", "--appid", appid)
	if out, err := fixture.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, out)
	}

	unpack := exec.Command(bash, filepath.Join(scripts, "miniapp_unpack.sh"),
		"--in", uploads,
		"--out", filepath.Join(root, "tasks", "1", "miniapp"),
		"--appid", appid,
		"--quality", "fast")
	unpack.Dir = runDir
	if out, err := unpack.CombinedOutput(); err != nil {
		t.Fatalf("unpack: %v\n%s", err, out)
	}
	work := filepath.Join(root, "tasks", "1", "miniapp", appid)
	if _, err := os.Stat(filepath.Join(work, "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	source, err := filepath.EvalSymlinks(filepath.Join(work, "source"))
	if err != nil {
		t.Fatalf("source symlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(source, "app.json")); err != nil {
		t.Fatalf("app.json missing in source %s: %v", source, err)
	}

	// 平台工具：路径相对 worker runDir（../miniapp/...），验证任务根内 .. 放行。
	ts := NewToolSet(nil, "worker")
	ts.SetRunDir(runDir)
	tool := ts.miniappAudit()
	in, _ := json.Marshal(map[string]any{
		"dir":   "../miniapp/" + appid + "/source",
		"appid": appid,
		"osv":   false,
	})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.IsError {
		t.Fatalf("miniapp_audit error: %s", toolResultText(t, res))
	}
	out := filepath.Join(runDir, "miniapp-audit")
	scan := exec.Command(py, filepath.Join(runDir, jsAuditScriptName),
		"--dir", source, "--out", out, "--appid", appid, "--no-osv")
	if raw, err := scan.CombinedOutput(); err != nil {
		t.Fatalf("scan: %v\n%s", err, raw)
	}
	report, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var r struct {
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
		t.Fatal(err)
	}
	foundEP, foundSecret := false, false
	for _, e := range r.Endpoints {
		if strings.Contains(e.URL, "api.example.com") {
			foundEP = true
		}
	}
	for _, s := range r.Secrets {
		if s.Type == "app_secret" {
			foundSecret = true
		}
	}
	if !foundEP || !foundSecret || len(r.Cloud.Env) == 0 || len(r.Cloud.Functions) == 0 {
		t.Fatalf("E2E 结果不完整: ep=%v secret=%v cloud=%+v", foundEP, foundSecret, r.Cloud)
	}
}
